修改点：

1. pgproto3/frontend.go 第408-419行区域 - 新增常量 AuthTypeSM3Password = 13 （需要对应数据库）

2. pgproto3/frontend.go 第24-56行区域（Frontend结构体）- 新增字段 authenticationSM3Password AuthenticationSM3Password

3. pgproto3/frontend.go 第421-451行（findAuthenticationMessageType方法）- 新增case分支：case AuthTypeSM3Password: return &f.authenticationSM3Password, nil

5. pgconn/pgconn.go 第429-435行之后 - 新增case处理：case *pgproto3.AuthenticationSM3Password，计算sm3密码并发送

6. pgconn/pgconn.go 第533-537行之后 - 新增辅助函数 hexSM3(s string) string

7. pgconn/pgconn.go 第539-546行区域 - 新增辅助函数 containsSCRAMSM3(mechanisms []string) bool，用于检测服务器是否支持SCRAM-SM3认证机制

8. 新建文件 pgconn/sm3.go - SM3哈希算法完整实现（可能需要对应数据库）

9. 新建文件 pgconn/auth_scram_sm3.go - 如果需要支持SCRAM-SM3认证方式

10. 新建文件 pgproto3/authentication_sm3_password.go - 创建AuthenticationSM3Password结构体及Decode/Encode/MarshalJSON/UnmarshalJSON方法
