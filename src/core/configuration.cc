// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "configuration.h"

#include "autogen/config.h"
#include "logger.h"
#include "spdlog/common.h"
#include "util/filesystem.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/platform.h"

#include <sstream>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include <fmt/format.h>

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
#include <bsd-getopt-long.h>
#endif

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

options::LogLevel options::default_log_level = options::LogLevel::warn;
options::LogType options::default_log_type = options::LogType::Stdout;
filesystem::path options::default_log_path = {};

static struct option long_driver_options[] = {
    // clang-format off
    {"config", required_argument, nullptr, 'c'},
    {"execute", required_argument, nullptr, 'e'},
    {"help", no_argument, nullptr, 'h'},
    {"interactive", no_argument, nullptr, 'i'},
    {"log-level", required_argument, nullptr, 'L'},
    {"autodoc", no_argument, nullptr, 'D'},
    {"test", no_argument, nullptr, 'T'},
    {"use-mock-data", no_argument, nullptr, 'M'},
    {"terminate-on-disconnect", no_argument, nullptr, 'N'},
    {"zeek", required_argument, nullptr, 'z'},
    {"version", no_argument, nullptr, 'v'},
    {nullptr, 0, nullptr, 0}
    // clang-format on
};

static void usage(const filesystem::path& name) {
    // clang-format off
    std::cerr << "\nUsage: " << name.filename().string() << format(
        " [options]\n"
        "\n"
        "  -D | --autodoc                   Output JSON documentating table schemas and exit.\n"
        "  -L | --log-level <LEVEL>         Set logging level (" LOG_LEVEL_HELP ") [default: warning]\n"
        "  -M | --use-mock-data             Let tables return only fake mock data for testing\n"
        "  -N | --terminate-on-disconnect   Let tables return only fake mock data for testing\n"
        "  -T | --test                      Run unit tests and exit\n"
        "  -c | --config <FILE>             Load configuration from file [default: {}]\n"
        "  -e | --execute <STMT>            SQL statement to execute immediately, then quit"
        "  -h | --help                      Show usage information\n"
        "  -i | --interactive               Spawn interactive console\n"
        "  -v | --version                   Print version information\n"
        "  -z | --zeek <host>[:port]        Connect to Zeek at given address\n"
        "\n",
        platform::configurationFile().string());
    // clang-format on
}

void Options::debugDump() {
    ZEEK_AGENT_DEBUG("configuration", "[option] version-number: {}", version_number);
    ZEEK_AGENT_DEBUG("configuration", "[option] mode: {}", to_string(mode));
    ZEEK_AGENT_DEBUG("configuration", "[option] agent-id: {}", agent_id);
    ZEEK_AGENT_DEBUG("configuration", "[option] instance-id: {}", instance_id);
    ZEEK_AGENT_DEBUG("configuration", "[option] config-file: {}",
                     (config_file ? *config_file : filesystem::path()).string());
    ZEEK_AGENT_DEBUG("configuration", "[option] interactive: {}", (interactive ? "true" : "false"));
    ZEEK_AGENT_DEBUG("configuration", "[option] log.level: {}",
                     (log_level ? options::to_string(*log_level) : "<not set>"));
    ZEEK_AGENT_DEBUG("configuration", "[option] log.type: {}", (log_type ? to_string(*log_type) : "<not set>"));
    ZEEK_AGENT_DEBUG("configuration", "[option] log.path: {}", (log_path ? log_path->string() : "<not set>"));
    ZEEK_AGENT_DEBUG("configuration", "[option] use-mock-data: {}", use_mock_data);
    ZEEK_AGENT_DEBUG("configuration", "[option] terminate-on-disconnect: {}", terminate_on_disconnect);
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.groups: {}", join(zeek_groups, ", "));
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.hello_interval: {}", to_string(zeek_hello_interval));
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.reconnect_interval: {}", to_string(zeek_reconnect_interval));
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.timeout: {}", to_string(zeek_timeout));
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.destinations: {}", join(zeek_destinations, ", "));
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.ssl_disable: {}", (zeek_ssl_disable ? "true" : "false"));
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.ssl_cafile: {}", zeek_ssl_cafile);
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.ssl_capath: {}", zeek_ssl_capath);
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.ssl_certificate: {}", zeek_ssl_certificate);
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.ssl_keyfile: {}", zeek_ssl_keyfile);
    ZEEK_AGENT_DEBUG("configuration", "[option] zeek.ssl_passphrase: {}", zeek_ssl_passphrase);
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

    Options _options;                // options currently in effect
    std::vector<std::string> _argv;  // command line options most recently provided.
    options::LogLevel old_log_level; // original log level to restore later.

    // Returns a set of options with all values at their default.
    static Options default_();
};

Options Configuration::Implementation::default_() {
    Options options;

    auto version = parseVersion(Version);
    if ( ! version )
        throw InternalError("cannot parse our own version number");

    options.version_number = *version;

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
        // Generate a fresh UUID as our agent's ID.
        options.agent_id = format("H{}", randomUUID());

        // Cache it.
        std::ofstream out(uuid_path, std::ios::out | std::ios::trunc);
        out << options.agent_id << "\n";
    }

    options.instance_id = format("I{}", randomUUID());

    auto path = platform::configurationFile();
    if ( filesystem::is_regular_file(path) )
        options.config_file = path;

    return options;
}

void Configuration::Implementation::apply(Options options) {
    // Set log option first so that the new value is active for subsequent
    // operations.
    setGlobalLogger(options.log_type ? *options.log_type : options::default_log_type,
                    options.log_level ? *options.log_level : options::default_log_level,
                    options.log_path ? *options.log_path : options::default_log_path);

    if ( options.mode == options::Mode::Test ) {
#ifndef DOCTEST_CONFIG_DISABLE
        if ( ! options.log_level )
            logger()->set_level(options::LogLevel::off);

        auto argv = preprocessArgv(true);
        platform::setenv("TZ", "GMT", 1);
        doctest::Context context(static_cast<int>(argv.size()), argv.data());
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
        int c =
            getopt_long(static_cast<int>(argv.size()), argv.data(), "DL:MNTc:e:hivz:", long_driver_options, nullptr);
        if ( c < 0 )
            return options;

        switch ( c ) {
            case 'L': {
                if ( auto level = options::log_level::from_str(optarg) ) {
                    options::default_log_level = *level; // this becomes new default for all config objects
                    options.log_level = level;
                }
                else
                    // unknown levels would turn logging off, so not setting
                    logger()->warn("unknown log level specified, ignoring");

                break;
            }

            case 'D': options.mode = options::Mode::AutoDoc; break;
            case 'M': options.use_mock_data = true; break;
            case 'N': options.terminate_on_disconnect = true; break;
            case 'T': options.mode = options::Mode::Test; break;
            case 'c': options.config_file = optarg; break;
            case 'e': options.execute = optarg; break;
            case 'i': options.interactive = true; break;
            case 'z': options.zeek_destinations.emplace_back(optarg); break;

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
            return result::Error(format("error reading {}: {}", config->config_file->string(), rc.error()));
    }
    else
        apply(std::move(*config));

    return Nothing();
}

Result<Nothing> Configuration::Implementation::read(const filesystem::path& path) {
    auto in = std::ifstream(path);
    if ( ! in.is_open() )
        return result::Error(format("cannot open configuration file {}", path.string()));

    return read(in, path);
}

// Get a value, typed correctly, if available.
template<typename T>
bool tomlValue(const toml::table& t, std::string_view path, T* dst) {
    using vtype = typename std::remove_reference_t<T>;

    auto n = t.at_path(path);
    if ( ! n )
        return false;

    if ( auto x = n.value<vtype>() ) {
        *dst = *x;
        return true;
    }
    else
        throw result::Error(format("cannot parse value for configuration option '{}'", path));
};

// Get an array, typed correctly, if available. This allows single values, too.
template<typename T>
bool tomlArray(const toml::table& t, std::string_view path, std::vector<T>* dst) {
    using vtype = typename std::remove_reference_t<T>;

    auto n = t.at_path(path);
    if ( ! n )
        return false;

    if ( auto x = n.as_array() ) {
        for ( const auto& i : *x ) {
            if ( auto v = i.template value<vtype>() )
                dst->push_back(*v);
            else
                throw result::Error(format("cannot parse value for configuration option '{}'", path));
        }

        return true;
    }

    else {
        vtype v;
        if ( ! tomlValue(t, path, &v) )
            return false;

        dst->push_back(v);
        return true;
    }
}

Result<Nothing> Configuration::Implementation::read(std::istream& in, const filesystem::path& path) {
    auto options = default_();
    options.config_file = path;

    try {
        auto tbl = toml::parse(in, path.native());
        tomlValue(tbl, "agent-id", &options.agent_id);

        std::string log_level;
        if ( tomlValue(tbl, "log.level", &log_level) ) {
            if ( auto rc = options::log_level::from_str(log_level) )
                options.log_level = *rc;
            else
                return rc.error();
        }

        std::string log_type;
        if ( tomlValue(tbl, "log.type", &log_type) ) {
            if ( auto x = options::log_type::from_str(log_type) )
                options.log_type = *x;
            else
                return x.error();
        }

        std::string log_path;
        if ( tomlValue(tbl, "log.path", &log_path) )
            options.log_path = log_path;

        tomlArray(tbl, "zeek.destination", &options.zeek_destinations);
        tomlArray(tbl, "zeek.groups", &options.zeek_groups);

        double interval;
        if ( tomlValue(tbl, "zeek.hello_interval", &interval) )
            options.zeek_hello_interval = to_interval(interval);

        if ( tomlValue(tbl, "zeek.reconnect_interval", &interval) )
            options.zeek_reconnect_interval = to_interval(interval);

        tomlValue(tbl, "zeek.ssl_cafile", &options.zeek_ssl_cafile);
        tomlValue(tbl, "zeek.ssl_capath", &options.zeek_ssl_capath);
        tomlValue(tbl, "zeek.ssl_certificate", &options.zeek_ssl_certificate);
        tomlValue(tbl, "zeek.ssl_disable", &options.zeek_ssl_disable);
        tomlValue(tbl, "zeek.ssl_keyfile", &options.zeek_ssl_keyfile);
        tomlValue(tbl, "zeek.ssl_passphrase", &options.zeek_ssl_passphrase);

        if ( tomlValue(tbl, "zeek.timeout", &interval) )
            options.zeek_timeout = to_interval(interval);

    } catch ( const toml::parse_error& err ) {
        return result::Error(err.what());
    } catch ( const result::Error& err ) {
        return err;
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

const Options& Configuration::options() const { return pimpl()->_options; }

Result<Nothing> Configuration::initFromArgv(int argc, const char* const* argv) {
    std::vector<std::string> vargv;
    vargv.reserve(argc);
    for ( auto i = 0; i < argc; i++ )
        vargv.emplace_back(argv[i]);

    ZEEK_AGENT_DEBUG("configuration", "setting command line arguments: {}", join(vargv, " "));
    return pimpl()->initFromArgv(std::move(vargv));
}

Result<Nothing> Configuration::read(const filesystem::path& path) {
    ZEEK_AGENT_DEBUG("configuration", "reading file {}", path.string());
    return pimpl()->read(path);
}

Result<Nothing> Configuration::read(std::istream& in, const filesystem::path& path) {
    ZEEK_AGENT_DEBUG("configuration", "reading stream associated with file {}", path.string());
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

    TEST_CASE("set log options") {
        Configuration cfg;

        auto old_default_log_level = options::default_log_level; // -L will change this

        SUBCASE("cli") {
            const char* argv[] = {"<prog>", "-L", "info"};
            cfg.initFromArgv(3, argv);
            CHECK_EQ(*cfg.options().log_level, options::LogLevel::info);
        }

        SUBCASE("config") {
            std::stringstream s;
            s << "[log]\n";
            s << "level = 'info'\n";
            s << "type = 'file'\n";
            s << "path = '/dev/null'\n";
            auto rc = cfg.read(s, "<test>");
            CHECK_EQ(*cfg.options().log_level, options::LogLevel::info);
            CHECK_EQ(*cfg.options().log_type, options::LogType::File);
            CHECK_EQ(*cfg.options().log_path, "/dev/null");
        }

        options::default_log_level = old_default_log_level;
    }

    TEST_CASE("set 'zeek'") {
        Configuration cfg;

        SUBCASE("cli") {
            const char* argv[] = {"<prog>", "-z", "host1", "-z", "host2:1234"};
            cfg.initFromArgv(5, argv);
            CHECK_EQ(cfg.options().zeek_destinations, std::vector<std::string>{"host1", "host2:1234"});
        }

        SUBCASE("config") {
            std::stringstream s;
            s << "[zeek]\n";
            s << "destination = ['host1', 'host2:1234']\n";
            auto rc = cfg.read(s, "<test>");
            CHECK_EQ(cfg.options().zeek_destinations, std::vector<std::string>{"host1", "host2:1234"});
        }

        SUBCASE("aggregate") {
            const char* argv[] = {"<prog>", "-z", "host1"};
            cfg.initFromArgv(3, argv);
            std::stringstream s;
            s << "[zeek]\n";
            s << "destination = 'host2:1234'\n";
            auto rc = cfg.read(s, "<test>");
            CHECK_EQ(cfg.options().zeek_destinations, std::vector<std::string>{"host2:1234", "host1"});
        }
    }

    TEST_CASE("set Zeek options") {
        Configuration cfg;

        std::stringstream s;
        s << "[zeek]\n";
        s << "groups = ['group1', 'group2']\n";
        s << "reconnect_interval = 1.0\n";
        s << "timeout = 2\n";
        s << "hello_interval = 3.5\n";
        s << "ssl_disable = true\n";
        s << "ssl_cafile = 'cafile'\n";
        s << "ssl_capath = 'capath'\n";
        s << "ssl_certificate = 'certificate'\n";
        s << "ssl_keyfile = 'keyfile'\n";
        s << "ssl_passphrase = 'passphrase'\n";

        auto rc = cfg.read(s, "<test>");
        CHECK_EQ(cfg.options().zeek_groups, std::vector<std::string>{"group1", "group2"});
        CHECK_EQ(cfg.options().zeek_reconnect_interval, 1s);
        CHECK_EQ(cfg.options().zeek_timeout, 2s);
        CHECK_EQ(cfg.options().zeek_hello_interval, 3.5s);
        CHECK_EQ(cfg.options().zeek_ssl_disable, true);
        CHECK_EQ(cfg.options().zeek_ssl_cafile, "cafile");
        CHECK_EQ(cfg.options().zeek_ssl_capath, "capath");
        CHECK_EQ(cfg.options().zeek_ssl_certificate, "certificate");
        CHECK_EQ(cfg.options().zeek_ssl_keyfile, "keyfile");
        CHECK_EQ(cfg.options().zeek_ssl_passphrase, "passphrase");
    }

    TEST_CASE("command line overrides config") {
        auto old_default_log_level = options::default_log_level;

        Configuration cfg;
        std::stringstream s;
        s << "log-level = 'warn'\n";
        const char* argv[] = {"<prog>", "-L", "info"};
        cfg.initFromArgv(3, argv);
        auto rc = cfg.read(s, "<test>");
        CHECK_EQ(*cfg.options().log_level, options::LogLevel::info);
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
