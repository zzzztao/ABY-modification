
add_executable(nonlinearActivation_test nonlinearActivation_test.cpp common/nonlinearActivation.cpp )
target_link_libraries(nonlinearActivation_test  ABY::aby ENCRYPTO_utils::encrypto_utils)
