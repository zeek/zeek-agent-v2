# Delete all 3rd party tests. Some of them we cannot disable otherwise (looking at you, "glob"!).

# Just overwrite the file ...
file(WRITE "@CMAKE_BINARY_DIR@/3rdparty/CTestTestfile.cmake" "")
