
add_executable(Binary_exponent_Float2 common/Decimal_Place_Float.cpp common/Binary_exponent_Float.cpp  test.cpp)
target_link_libraries(Binary_exponent_Float2 ABY::aby ENCRYPTO_utils::encrypto_utils)
