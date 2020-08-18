# a*b具体分析

- ABY phase总共分了

  P_INIT, P_CIRCUIT, P_NETWORK, P_BASE_OT, P_OT_EXT, P_GARBLE, P_ONLINE 7个阶段

  SETUP = P_OT_EXT+P_GARBLE  

  TOTAL =  SETUP + P_ONLINE 

- new ABYPatty  // new party  

  - P_INIT //没有参数，返回一个bool

    - Init(); //m_vSockets = 2 ，建立2个连接一个receiver一个sender 初始化了m_nMyNumInBits = 0; m_nHelperThreads = 2;   m_vSockets.resize(2);  返回一个true

      m_pCircuit = NULL;

    P_INIT STOP

  - P_CIRCUIT  //初始话算术电路参数

    - InitCircuit(bitlen, reservegates, abycircdir) 

      //bitlen为位数，reservegates为最大电路门个数，abycircdir 为一个电路路径 输出为../../bin/circ/ 输出一个bool

      - m_pCircuit = new ABYCircuit(reservegates); 

        //m_nMaxVectorSize{1}, m_nMaxDepth{0}

        这是初始化电路参数s_bool，S_YAO, S_ARITH, 算术以bitlen位数确定生成电路以32为例

        m_vSharings[S_ARITH] = new ArithSharing<uint32_t>(S_ARITH, m_eRole, 1, m_pCircuit, m_cCrypt.get(), m_eMTGenAlg); 
      
        // S_ARITH代表电路 ，m_eRole角色，sharebitlen，m_pCircuit，m_cCrypt.get()为密码参数，m_eMTGenAlg为mts构造方式
      
        - Init（）初始化算术电路参数 
      
        - new ArithmeticCircuit 里面继续Init（）这个初始话是and门，cons门的个数
    
    P_CIRCUIT STOP

- ABYPatty STOP

- party->GetSharings(); //获取输入电路类型

- (ArithmeticCircuit*) sharings[S_ARITH] //一个算术电路

- Arith_circ->PutINGate //输入一个值

- Arith_circ->PutMULGate //计算乘法

- ABYParty::ExecCircuit() 

  - ConnectAndBaseOTs();

    -  P_NETWORK

      - EstablishConnection（）//建立网络连接，初始化m_tComm	

    - P_NETWORK  STOP

    - P_BASE_OT

      - PrepareSetupPhase（） //传入参数 m_tComm指针

        ​		m_tSetupChan = new channel 建立了一个setup channel通道

        ​		初始化BaseOT参数

        ​		若使用MT_PAILLIER时该阶段生成密钥m_cPaillierMTGen->keyExchange(m_tSetupChan	

    - P_BASE_OT STOP

  - P_TOTAL

    - P_SETUP

      m_vSharings[i]->PrepareSetupPhase(m_pSetup.get()）//遍历执行各个电路的PrepareSetup

      ​	主要以Arith的PrepareSetupPhase（m_pSetup.get）为例  m_nMTS 乘法三元组个数

      - ​	InitMTs()

        ​	//用随机值填充m_vA ,m_vB ;   m_vC,m_vS填充了m_nMTs*m_nTypeBitLen个0 其他初始化大	小为1 

        ​	然后搞了个结构体指针 pgentask = (PKMTGenVals*) malloc(sizeof(PKMTGenVals)); 

         	将A，B，C，m_nMTs, m_nTypeBitLen赋值进去，然后push_back到  vector<PKMTGenVals*>m_vPKMTGenTasks;

      - P_OT_EXT

        ​	m_pSetup->PerformSetupPhase(); //此阶段 主要是OT_EXT和在线计算乘法三元组

        ​		WakeupWorkerThreads(e_MTPaillier);

        ​					switch (job) 

        ​								bSuccess = m_pCallback->ThreadRunPaillierMTGen(threadid);

        ​										初始化分块参数，线程参数等

        ​													根据角色computeArithmeticMTs

           	 success &= WaitWorkerThreads(); //

      - P_OT_EXT STOP

      - P_GARBLE

        ​	[S_YAO]->PerformSetupPhase/这个阶段是初始化yao 

      - P_GARBLE STOP

    - P_SETUP STOP

    - P_ONLINE

        ​	EvaluateCircuit() //在线计算

        ​	m_tPartyChan = new channel

        ​	m_vSharings[i]->PrepareOnlinePhase();//遍历电路 每个电路都跑 主要看一下算术电路

        ​			//获取自己输入总bitlen，输出总bitlen ，获取另外一方

        ​			//初始化m_vInputShareSndBuf 随机数

        ​			//m_vOutputShareSndBuf， m_vInputShareRcvBuf，m_vOutputShareRcvBuf 为0

        ​		InitNewLayer()
    
        ​				// m_vInputShareSndBuf  //掩码
  
          //其他部分 Evaluate Circuit layerwise
  
    - P_ONLINE STOP
  
  - P_TOTAL
  
    
    $$
    P_0:a_0,b_0 ∈_RZ_2^l
    $$
    
    
    乘法三元组计算
    
    a0，b0，c0 ，a1，b1，c1
    
    enc（a0）
    
    enc（b0）
    
    发送enc（a0），enc（b0）
    
    计算c0 = enc（a0）^b1 + enc(b0)^a1 mod m_remotepub->n_squared
    
    
    
    ```mermaid
    graph TD
    	A-->b
    	A-->c
    	
    
    ```
    
    
    
    
    
    //没懂这一步
    
    初始化一个y值为0，maxShareBitLength位
    
    z = c0
    
    z = z^y mod m_remotepub->n_squared
    
    z = z *c0
    
    z = z mod m_remotepub->n_squared
    
    
    
    初始化掩码r
    
    enc(r)
    
    z = z * enc(r)  mod
    
    
    
    计算c1
    
    c1 = a1 * b1 -r mod 2^k
    
    发送z
    
    解密z
    
    计算c0 = a0 *b0 + dec c1
    
    
    
    
    $$
    P0：A0 ，B0 ，
    
    P1：A1，B1，C1 = A1*B1 -r
    
    P0-->P1：Enc（A0），Enc（B0）
    
    P1: temp_C1 = Eec(A0)^B1 * Enc(B0)^A1
    	for(last ... 0)
    		z = c1[last]
    		y = 0;
    		y = 2^maxShareBlitLength
    	
    		z = z^y 
    		z = z * c1[last - 1]
    	init r
    	Enc(r)
    	temp_C1 = z * Enc(r) = Eec(A0)^B1 * Enc(B0)^A1 * Enc(r)
    	
    	for(1 .. n)
    		temp = r mod 2^maxShareBlitLength
    		r = r >> maxShareBitLength 
    		C1 = C1 * C1 - temp mod 2^maxShareBlitLength
    P1 -->P0 temp_C1
    
    P0: temp = Dec(temp_c1)
    	C0 = temp mod 2^ShareBitLength
    	temp = temp >> maxShareBitLength
    	C0 = A1 * B1 + C0
    	C0 = C0 mod 2^ShareBitLength
    	
    $$
    
    
    
    
    ​    
  
  
  
    

