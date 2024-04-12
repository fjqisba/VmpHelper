## 关于vmp流程的研究

有下面几种函数情况:

#### 流程1

普通指令 -> vmp entry -> vmp exit -> 普通指令

靠基本模式匹配就行了

情况2:

函数中存在call指令

普通指令 -> vmp entry -> vm call -> 

