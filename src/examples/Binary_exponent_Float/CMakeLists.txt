
add_executable(Binary_exponent_Float test.cpp common/Binary_exponent_Float.cpp common/Decimal_Place_Float.cpp)
target_link_libraries(Binary_exponent_Float ABY::aby ENCRYPTO_utils::encrypto_utils)
