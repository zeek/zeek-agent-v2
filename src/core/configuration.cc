// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "configuration.h"

#include "autogen/config.h"
#include "logger.h"
#include "spdlog/common.h"
#include "util/filesystem.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/platform.h"

#include <memory>
#include <sstream>
#include <system_error>
#include <utility>
#include <vector>

#include <getopt.h>
#include <string.h>
#include <uuid.h>

#include <toml++/toml.h>

#define DOCTEST_CONFIG_NO_UNPREFIXED_OPTIONS
#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_OPTIONS_PREFIX "test-"

#include "util/testing.h"

#ifndef NDEBUG
#define LOG_LEVEL_HELP "info,warning,error,critical"
#else
#define LOG_LEVEL_HELP "trace,debug,info,warning,error,critical"
#endif

using namespace zeek::agent;

spdlog::level::level_enum options::default_log_level = spdlog::level::warn;

static struct option long_driver_options[] = {
    // clang-format off
    {"config", required_argument, nullptr, 'c'},
    {"execute", required_argument, nullptr, 'e'},
    {"help", no_argument, nullptr, 'h'},
    {"interactive", no_argument, nullptr, 'i'},
    {"log-level", required_argument, nullptr, 'L'},
    {"test", no_argument, nullptr, 'T'},
    {"use-mock-data", no_argument, nullptr, 'M'},
    {"version", no_argument, nullptr, 'v'},
    {nullptr, 0, nullptr, 0}
    // clang-format on
};

static void usage(const filesystem::path& name) {
    // clang-format off
    std::cerr << "\nUsage: " << name.filename().native() << format(
        " [options]\n"
        "\n"
        "  -L | --log-level <LEVEL>    Set logging level (" LOG_LEVEL_HELP ") [default: warning]\n"
        "  -M | --use-mock-data        Let tables return only fake mock data for testing\n"
        "  -T | --test                 Run unit tests and exit\n"
        "  -c | --config <FILE>        Load configuration from file [default: {}]\n"
        "  -e | --execute <STMT>       SQL statement to execute immediately, then quit"
        "  -h | --help                 Show usage information\n"
        "  -i | --interactive          Spawn interactive console\n"
        "  -v | --version              Print version information\n"
        "\n",
        platform::configurationFile().native());
    // clang-format on
}

void Options::debugDump() {
    ZEEK_AGENT_DEBUG("configuration", "[option] agent-id: {}", agent_id);
    ZEEK_AGENT_DEBUG("configuration", "[option] config-file: {}",
                     (config_file ? *config_file : filesystem::path()).native());
    ZEEK_AGENT_DEBUG("configuration", "[option] interactive: {}", (interactive ? "true" : "false"));
    ZEEK_AGENT_DEBUG("configuration", "[option] log-level: {}",
                     (log_level ? spdlog::level::to_short_c_str(*log_level) : "<not set>"));
    ZEEK_AGENT_DEBUG("configuration", "[option] run-tests: {}", run_tests);
    ZEEK_AGENT_DEBUG("configuration", "[option] use-mock-data: {}", use_mock_data);
}

template<>
struct Pimpl<Configuration>::Implementation {
    // Returns a copy of the current command line options as an array of char
    // pointers that can be passed into `getopt()`. If `include_doctest` is
    // false, skips any options belonging to doctest
    std::vector<char*> preprocessArgv(bool include_doctest);

    // Applies the current set of command line options to an existing options
    // instance, returning the updated set.
    Result<Options> addArgv(Options options);

    // Puts a new set of options into effect.
    void apply(Options options);

    // Processes a configuration file.
    Result<Nothing> read(const filesystem::path& path);

    // Processes a configuration file's content from an already open stream.
    Result<Nothing> read(std::istream& in, const filesystem::path& path);

    // Sets a set of command line options.
    Result<Nothing> initFromArgv(std::vector<std::string> argv);

    Options _options;                        // options currently in effect
    std::vector<std::string> _argv;          // command line options most recently provided.
    spdlog::level::level_enum old_log_level; // original log level to restore later.

    // Returns a set of options with all values at their default.
    static Options default_();
};

Options Configuration::Implementation::default_() {
    Options options;

    // Attempt to read our agent's ID from previously created cache file.
    auto uuid_path = (platform::dataDirectory() / "uuid").native();
    if ( filesystem::is_regular_file(uuid_path) ) {
        if ( auto in = std::ifstream(uuid_path) ) {
            std::string line;
            std::getline(in, line);

            if ( auto uuid = uuids::uuid::from_string(line) )
                options.agent_id = uuids::to_string(*uuid);
        }
    }

    if ( options.agent_id.empty() ) {
        std::random_device rd;
        auto seed_data = std::array<int, std::mt19937::state_size>{};
        std::generate(std::begin(seed_data), std::end(seed_data), std::ref(rd));
        std::seed_seq seq(std::begin(seed_data), std::end(seed_data));
        std::mt19937 generator(seq);
        auto uuid = uuids::uuid_random_generator(generator)();

        // Generate a fresh UUID as our agent's ID.
        options.agent_id = uuids::to_string(uuid);

        // Cache it.
        std::ofstream out(uuid_path, std::ios::out | std::ios::trunc);
        out << options.agent_id << "\n";
    }

    auto path = platform::configurationFile();
    if ( filesystem::is_regular_file(path) )
        options.config_file = path;

    return options;
}

void Configuration::Implementation::apply(Options options) {
    // Set options level first so that the new value is active for subsequent
    // operation.s
    if ( options.log_level )
        logger()->set_level(*options.log_level);
    else
        logger()->set_level(options::default_log_level);

    if ( options.run_tests ) {
#ifndef DOCTEST_CONFIG_DISABLE
        if ( ! options.log_level )
            logger()->set_level(spdlog::level::off);

        auto argv = preprocessArgv(true);
        doctest::Context context(argv.size(), argv.data());
        exit(context.run());
#else
        logger::fatalError("unit tests not compiled in");
#endif
    }

    _options = std::move(options);
    _options.debugDump();
}

std::vector<char*> Configuration::Implementation::preprocessArgv(bool include_doctest) {
    std::vector<char*> result;

    for ( auto& x : _argv ) {
        if ( include_doctest || x.find("--" DOCTEST_CONFIG_OPTIONS_PREFIX) != 0 )
            result.push_back(const_cast<char*>(x.c_str()));
    }

    return result;
}

Result<Options> Configuration::Implementation::addArgv(Options options) {
    auto argv = preprocessArgv(false);

    // Restart getopt(). See https://stackoverflow.com/a/60484617 &&
    // https://github.com/dnsdb/dnsdbq/commit/efa68c0499c3b5b4a1238318345e5e466a7fd99f
#ifdef HAVE_LINUX
    optind = 0;
#else
    optind = 1;
    optreset = 1;
#endif

    while ( true ) {
        int c = getopt_long(argv.size(), argv.data(), "L:MTc:e:hiv", long_driver_options, nullptr);
        if ( c < 0 )
            return options;

        switch ( c ) {
            case 'L': {
                auto level = spdlog::level::from_str(optarg);
                if ( level != spdlog::level::off ) {
                    options::default_log_level = level; // this becomes new default for all config objects
                    options.log_level = level;
                }
                else
                    // unknown levels would turn logging off, so not setting
                    logger()->warn("unknown log level specified, ignoring");

                break;
            }

            case 'M': options.use_mock_data = true; break;
            case 'T': options.run_tests = true; break;
            case 'c': options.config_file = optarg; break;
            case 'e': options.execute = optarg; break;
            case 'i': options.interactive = true; break;

            case 'v': std::cerr << "Zeek Agent v" << VersionLong << std::endl; exit(0);
            case 'h': usage(argv[0]); exit(0);
            default: usage(argv[0]); exit(1);
        }
    }
}

Result<Nothing> Configuration::Implementation::initFromArgv(std::vector<std::string> argv) {
    _argv = std::move(argv);

    auto config = addArgv(default_());
    if ( ! config )
        return result::Error(format("error: {}", config.error()));

    if ( config->config_file ) {
        auto rc = read(*config->config_file);
        if ( ! rc )
            return result::Error(format("error reading {}: {}", config->config_file->native(), rc.error()));
    }

    apply(std::move(*config));
    return Nothing();
}

Result<Nothing> Configuration::Implementation::read(const filesystem::path& path) {
    auto in = std::ifstream(path);
    if ( ! in.is_open() )
        return result::Error(format("cannot open configuration file ", path.native()));

    return read(in, path);
}

template<typename T>
Result<T> tomlSafeGet(const toml::table& tbl, std::string key) {
    if ( auto x = tbl[key].value<T>() )
        return *x;
    else
        return result::Error(format("cannot parse value for configuration option '{}'", key));
}

Result<Nothing> Configuration::Implementation::read(std::istream& in, const filesystem::path& path) {
    auto options = default_();
    options.config_file = path;

    toml::table tbl;
    try {
        tbl = toml::parse(in, path.native());
    } catch ( const toml::parse_error& err ) {
        return result::Error(err.what());
    }

    if ( tbl.contains("agent-id") ) {
        auto x = tomlSafeGet<std::string>(tbl, "agent-id");
        if ( x )
            options.agent_id = *x;
        else
            return x.error();
    }

    if ( tbl.contains("log-level") ) {
        auto x = tomlSafeGet<std::string>(tbl, "log-level");
        if ( ! x )
            return x.error();

        auto level = spdlog::level::from_str(*x);
        if ( level == spdlog::level::off )
            return result::Error("unknown log level");

        options.log_level = level;
    }

    auto rc = addArgv(options);
    if ( ! rc )
        return rc.error();

    apply(std::move(*rc));
    return Nothing();
}

Configuration::Configuration() {
    ZEEK_AGENT_DEBUG("configuration", "creating instance");
    pimpl()->apply(pimpl()->default_());
    pimpl()->old_log_level = logger()->level();
}

Configuration::~Configuration() {
    ZEEK_AGENT_DEBUG("configuration", "destroying instance");
    logger()->set_level(pimpl()->old_log_level);
}

const Options& Configuration::options() const {
    Synchronize _(this);
    return pimpl()->_options;
}

Result<Nothing> Configuration::initFromArgv(int argc, const char* const* argv) {
    Synchronize _(this);

    std::vector<std::string> vargv;
    for ( auto i = 0; i < argc; i++ )
        vargv.push_back(argv[i]);

    ZEEK_AGENT_DEBUG("configuration", "setting command line arguments: {}", join(vargv, " "));
    return pimpl()->initFromArgv(std::move(vargv));
}

Result<Nothing> Configuration::read(const filesystem::path& path) {
    Synchronize _(this);
    ZEEK_AGENT_DEBUG("configuration", "reading file {}", path.native());
    return pimpl()->read(path);
}

Result<Nothing> Configuration::read(std::istream& in, const filesystem::path& path) {
    Synchronize _(this);
    ZEEK_AGENT_DEBUG("configuration", "reading stream associated with file {}", path.native());
    return pimpl()->read(in, path);
}

TEST_SUITE("Configuration") {
    TEST_CASE("set 'agent-id'") {
        Configuration cfg;

        SUBCASE("config") {
            std::stringstream s;
            s << "agent-id = 'my-agent'\n";
            auto rc = cfg.read(s, "<test>");
            CHECK_EQ(cfg.options().agent_id, "my-agent");
        }
    }

    TEST_CASE("set 'interactive'") {
        Configuration cfg;

        SUBCASE("cli") {
            const char* argv[] = {"<prog>", "-i"};
            cfg.initFromArgv(2, argv);
            CHECK(cfg.options().interactive);
        }
    }

    TEST_CASE("set 'execute'") {
        Configuration cfg;

        SUBCASE("cli") {
            const char* argv[] = {"<prog>", "-e", ".tables"};
            cfg.initFromArgv(3, argv);
            CHECK_EQ(cfg.options().execute, ".tables");
        }
    }

    TEST_CASE("set 'log-level'") {
        Configuration cfg;

        auto old_default_log_level = options::default_log_level;

        SUBCASE("cli") {
            const char* argv[] = {"<prog>", "-L", "info"};
            cfg.initFromArgv(3, argv);
            CHECK_EQ(*cfg.options().log_level, spdlog::level::info);
        }

        SUBCASE("config") {
            std::stringstream s;
            s << "log-level = 'info'\n";
            auto rc = cfg.read(s, "<test>");
            CHECK_EQ(*cfg.options().log_level, spdlog::level::info);
        }

        options::default_log_level = old_default_log_level;
    }

    TEST_CASE("command line overrides config") {
        auto old_default_log_level = options::default_log_level;

        Configuration cfg;
        std::stringstream s;
        s << "log-level = 'warn'\n";
        const char* argv[] = {"<prog>", "-L", "info"};
        cfg.initFromArgv(3, argv);
        auto rc = cfg.read(s, "<test>");
        CHECK_EQ(*cfg.options().log_level, spdlog::level::info);
        CHECK_EQ(*cfg.options().config_file, "<test>");

        options::default_log_level = old_default_log_level;
    }

    TEST_CASE("broken config") {
        Configuration cfg;

        SUBCASE("syntax error") {
            std::stringstream s;
            s << "agent-id = '\n";
            auto rc = cfg.read(s, "<test>");
            CHECK_EQ(rc, result::Error("Error while parsing string: encountered end-of-file"));
        }

        SUBCASE("wrong type") {
            std::stringstream s;
            s << "agent-id = 3.14\n";
            auto rc = cfg.read(s, "<test>");
            CHECK_EQ(rc, result::Error("cannot parse value for configuration option 'agent-id'"));
        }
    }
}
