# ABY_TEST

本实验仅用于学术研究，不能保证其没有问题！



### aby：

A Framework for Efficient Mixed-Protocol Secure Two-Party Computation

By *Daniel Demmler, Thomas Schneider and Michael Zohner* ([ENCRYPTO](http://www.encrypto.de/), TU Darmstadt)
in [Network and Distributed System Security Symposium (NDSS'15)](http://www.internetsociety.org/events/ndss-symposium-2015). [Paper available here.](http://thomaschneider.de/papers/DSZ15.pdf)

开源地址：https://github.com/encryptogroup/ABY



### 功能实现：

对已有框架做了些修改，添加了全新乘法三元组协商协议、e的指数计算、牛顿除法计算等、封装了激励函数等方法

1. 修改了乘法三元组协议（done）
2. 实现e^x计算 效率低 有优化空间 （done）
3. 使用高效的乘法与加法去逼近小数除法 （done）
4. 做一些激励函数的封装（done）



功能实现在../examples



### 环境依赖：

1. Linux（Centos 7 & Ubuntu 16.10++）
2. g++ >= 9
3. make
4. cmake >= 3.20
5. libgmp-dev
6. libssl-dev
7. libboost-all-dec >=1.66



###  编译方式：

1. git clone https://github.com/zzzztao/ABY_TEST.git

2. cd ABY_TEST

3. mkdir build && cd build

4. cmake ..

5. make -j4

6. sudo make install

   

可参考aby例子运行方式：

- Make sure you have build ABY as described above and set the `-DABY_BUILD_EXE=On` option and the application's binary was created in `bin/` inside the build directory.
- To locally execute an application, run the created executable from **two different terminals** and pass all required parameters accordingly.
- By default applications are tested locally (via sockets on `localhost`). You can run them on two different machines by specifying IP addresses and ports as parameters.
- **Example:** The Millionaire's problem requires to specify the role of the executing party. All other parameters will use default values if they are not set. You execute it locally with: `./millionaire_prob_test -r 0` and `./millionaire_prob_test -r 1`, each in a separate terminal.
- You should get some debug output for you to verify the correctness of the computation.
- Performance statistics can be turned on setting `#define PRINT_PERFORMANCE_STATS 1` in `src/abycore/ABY_utils/ABYconstants.h` in [line 33](https://github.com/encryptogroup/ABY/blob/public/src/abycore/ABY_utils/ABYconstants.h#L33).



### 待优化问题：

1. 可将乘法计算放在算术电路中运行
2. 指数计算可以使用定点数进行提速



   
