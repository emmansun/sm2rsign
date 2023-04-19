# sm2rsign
Ring Signature Schemes Based on SM2 Digital Signature Algorithm

[![test](https://github.com/emmansun/sm2rsign/actions/workflows/go.yml/badge.svg)](https://github.com/emmansun/sm2rsign/actions/workflows/go.yml)
![GitHub go.mod Go version (branch)](https://img.shields.io/github/go-mod/go-version/emmansun/sm2rsign)

本实验性实现基于SM2数字签名算法的环签名方案，参考资料：
- [基于SM2数字签名算法的环签名方案](http://www.jcr.cacrnet.org.cn/CN/10.13868/j.cnki.jcr.000472)
- [基于SM2密码算法的环签名方案的研究与设计](https://www.wangan.com/p/7fyg8kdf13655a55)

其实这两个方案除了签名参与者的随机数生成方式不同，其它没有区别。本实验性实现暂未考虑环签名的ASN.1编码。
