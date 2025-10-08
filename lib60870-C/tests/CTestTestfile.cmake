# CMake generated Testfile for 
# Source directory: C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests
# Build directory: C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(all_tests "C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/Debug/tests.exe")
  set_tests_properties(all_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/CMakeLists.txt;61;add_test;C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(all_tests "C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/Release/tests.exe")
  set_tests_properties(all_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/CMakeLists.txt;61;add_test;C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(all_tests "C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/MinSizeRel/tests.exe")
  set_tests_properties(all_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/CMakeLists.txt;61;add_test;C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(all_tests "C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/RelWithDebInfo/tests.exe")
  set_tests_properties(all_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/CMakeLists.txt;61;add_test;C:/Users/z005653n/Desktop/lib60870/lib60870-C/tests/CMakeLists.txt;0;")
else()
  add_test(all_tests NOT_AVAILABLE)
endif()
