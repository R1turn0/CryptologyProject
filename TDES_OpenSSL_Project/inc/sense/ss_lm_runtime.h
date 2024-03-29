/** 
*   @file       ss_lm_runtime.h
*   @brief      许可管理用的导入头文件.  
*               对应动态库: slm_runtime.dll/slm_runtime_dev.dll 
*               对应静态库: slm_runtime_api.lib/slm_runtime_api_dev.lib 
*
*   使用许可调用顺序：
*
*       第一步，调用slm_init函数进行全局初始化
*       第二步，调用slm_login函数登录许可（硬件许可，网络许可，云许可，软许可）
*       第三步，调用许可操作函数，例如slm_keepalive slm_encrypt slm_decrypt等操作
*       第四步，调用slm_logout函数，登出当前许可
*       第五步，程序退出时，调用slm_cleanup函数反初始化（可选调用）
*   @version   2.1.0
*   @date      2013-2020
*
*/
#ifndef __SS_LM_RUMTIME_H__
#define __SS_LM_RUMTIME_H__
#include "ss_define.h"
#include "ss_error.h"

#ifdef  _MSC_VER
#pragma comment(linker, "/defaultlib:ws2_32.lib")
#pragma comment(linker, "/defaultlib:iphlpapi.lib")
#pragma comment(linker, "/defaultlib:psapi.lib")
#pragma comment(linker, "/defaultlib:Shlwapi.lib")
#pragma comment(lib, "rpcrt4.lib")


#if _MSC_VER >= 1900   // 1900是VS2015的版本号，解决静态库在VS2015下编译失败的问题
#pragma comment(linker, "/defaultlib:legacy_stdio_definitions.lib")
#endif  // MSC_VER

#endif//???

/** 硬件锁闪灯颜色：蓝色 */
#define LED_COLOR_BLUE      0
/** 硬件锁闪灯颜色：红色 */
#define LED_COLOR_RED       1

/** 硬件锁闪灯控制：关闭 */
#define LED_STATE_CLOSE     0
/** 硬件锁闪灯控制：打开 */
#define LED_STATE_OPEN      1
/** 硬件锁闪灯控制：闪烁 */
#define LED_STATE_SHRINK    2

/** Virbox许可服务 消息处理回调函数（当前版本 SLM_CALLBACK_VERSION02 ) ，其中lparam暂时没有使用 */
typedef SS_UINT32 (SSAPI *SS_CALL_BACK)(SS_UINT32   message,void*       wparam,void*       lparam);
    
//============================================================
//   Virbox许可服务 回调消息 message 类型
//============================================================
/** 回调消息类型：信息提示 */
#define SS_ANTI_INFORMATION			0x0101
/** 回调消息类型：警告（回调参数wparam代表警告类型）*/
#define SS_ANTI_WARNING				0x0102
/** 回调消息类型：异常 */
#define SS_ANTI_EXCEPTION			0x0103
/** 回调消息类型：暂保留 */
#define SS_ANTI_IDLE				0x0104

/** 回调消类型：服务启动 */
#define SS_MSG_SERVICE_START        0x0200
/** 回调消类型：服务停止 */
#define SS_MSG_SERVICE_STOP         0x0201
/** 回调消类型：锁可用（插入锁或 Virbox许可服务 启动时锁已初始化完成），回调参数wparam 代表锁号 */
#define SS_MSG_LOCK_AVAILABLE       0x0202
/** 回调消类型：锁无效（锁已拔出），回调参数wparam 代表锁号 */
#define SS_MSG_LOCK_UNAVAILABLE     0x0203
/** 回调消类型：云账号登录，回调参数wparam 代表已登录云账号用户名 */
#define SS_MSG_CLOUD_USER_LOGIN     0x0204
/** 回调消类型：云账号登出，回调参数wparam 代表已登出云账号用户名 */
#define SS_MSG_CLOUD_USER_LOGOUT    0x0205

//============================================================
//   回调消息类型：警告类型SS_ANTI_WARNING的值 wparam 参数
//============================================================
/** 检测到有补丁程序注入到目标程序中，一般指盗版程序的补丁动态库等文件出现在当前进程空间 */
#define SS_ANTI_PATCH_INJECT		0x0201
/** 系统模块异常，可能存在劫持行为，如一些位于系统目录的动态库（hid.dll、lpk.dll）等，从错误的目录加载 */
#define SS_ANTI_MODULE_INVALID		0x0202
/** 检测到程序被调试器附加的行为，如通过Ollydbg、Windbg对程序进行附加调试 */
#define SS_ANTI_ATTACH_FOUND		0x0203
/** 意为：无效的线程。暂未定义，保留 */
#define SS_ANTI_THREAD_INVALID		0x0204
/** 检测到反调试线程运行状态异常，可能被恶意攻击，如线程被手动挂起等 */
#define SS_ANTI_THREAD_ERROR		0x0205
/** 检测到对模块数据的CRC验证失败，可能存在恶意分析行为，对进程中的模块设置断点或篡改等 */
#define SS_ANTI_CRC_ERROR			0x0206
/** 检测到软件运行环境中有调试器存在，如Ollydbg、Windbg */
#define SS_ANTI_DEBUGGER_FOUND		0x0207
//=============================================================

/** 时钟校准随机数种子长度 */
#define SLM_FIXTIME_RAND_LENGTH     8

/** SS_CALL_BACK的版本 （支持开发者API密码的版本）*/
#define SLM_CALLBACK_VERSION02      0x02

/** 内存托管最大长度（字节）*/
#define  SLM_MEM_MAX_SIZE           2048

/** 代码执行，最大输入缓冲区大小（字节） */
#define SLM_MAX_INPUT_SIZE          1758
/** 代码执行，最大输出缓冲区大小（字节） */
#define SLM_MAX_OUTPUT_SIZE         1758

/** 加解密最大缓冲区最大长度（字节）*/
#define SLM_MAX_USER_CRYPT_SIZE     1520

/** 用户验证数据最大长度（字节）*/
#define SLM_MAX_USER_DATA_SIZE      2048

/** 用户数据区写入最大长度（字节）*/
#define SLM_MAX_WRITE_SIZE          1904

/** 请求硬件锁设备私钥签名的数据前缀，见slm_sign_by_device */
#define SLM_VERIFY_DEVICE_PREFIX    "SENSELOCK"

/** 请求硬件锁设备私钥签名的数据大小，见slm_sign_by_device */
#define SLM_VERIFY_DATA_SIZE        41

/** 硬件锁设备芯片号的长度（二进制字节）*/
#define SLM_LOCK_SN_LENGTH          16

/** 开发商ID长度（二进制字节）*/
#define SLM_DEVELOPER_ID_SIZE       8

/** 指定登录网络锁服务器名称最大长度（字符串）*/
#define SLM_MAX_SERVER_NAME         32

/** 指定登录云锁用户token最大长度（字符串）*/
#define SLM_MAX_ACCESS_TOKEN_LENGTH 64

/** 指定登录云锁服务器地址最大长度（字符串）*/
#define SLM_MAX_CLOUD_SERVER_LENGTH 100

/** 碎片代码种子长度（二进制字节）*/
#define SLM_SNIPPET_SEED_LENGTH     32

/** 开发者API密码长度（二进制字节）*/
#define SLM_DEV_PASSWORD_LENGTH     16

/** 用户GUID最大长度（字符串） */
#define SLM_CLOUD_MAX_USER_GUID_SIZE 	        128	

/** 一般的GUID长度，二进制 */
#define SLM_GUID_LENGTH 	                16	

/** 硬件锁锁内文件类型：数据文件 */
#define SLM_FILE_TYPE_BINARY                    0
/** 硬件锁锁内文件类型：可执行文件文件 */
#define SLM_FILE_TYPE_EXECUTIVE                 1
/** 硬件锁锁内文件类型：密钥文件 */
#define SLM_FILE_TYPE_KEY                       2

/** 硬件锁锁内文件属性：开发者可读 */
#define SLM_FILE_PRIVILEGE_FLAG_READ            0x01
/** 硬件锁锁内文件属性：开发者可写 */
#define SLM_FILE_PRIVILEGE_FLAG_WRITE           0x02
/** 硬件锁锁内文件属性：开发者可使用（密钥文件） */
#define SLM_FILE_PRIVILEGE_FLAG_USE             0x04
/** 硬件锁锁内文件属性：开发者可远程升级 */
#define SLM_FILE_PRIVILEGE_FLAG_UPDATE          0x08

/** 硬件锁锁内文件属性：可读 */
#define SLM_FILE_PRIVILEGE_FLAG_ENTRY_READ      0x10
/** 硬件锁锁内文件属性：深思可写 */
#define SLM_FILE_PRIVILEGE_FLAG_ENTRY_WRITE     0x20
/** 硬件锁锁内文件属性：深思可使用（密钥文件）*/
#define SLM_FILE_PRIVILEGE_FLAG_ENTRY_USE       0x40
/** 硬件锁锁内文件属性：深思可远程升级 */
#define SLM_FILE_PRIVILEGE_FLAG_ENTRY_UPDATE    0x80



/** 许可登录模式：自动选择 */
#define SLM_LOGIN_MODE_AUTO						0x0000
/** 许可登录模式：指定登录本地锁 */
#define SLM_LOGIN_MODE_LOCAL_DONGLE				0x0001
/** 许可登录模式：指定登录网络锁 */
#define SLM_LOGIN_MODE_REMOTE_DONGLE			0x0002
/** 许可登录模式：指定登录云锁 */
#define SLM_LOGIN_MODE_CLOUD					0x0004
/** 许可登录模式：指定登录本地软锁 */
#define SLM_LOGIN_MODE_LOCAL_SLOCK 				0x0008
/** 许可登录模式：指定登录远程软锁 */
#define SLM_LOGIN_MODE_REMOTE_SLOCK				0x0010

/** 许可登录控制：查找所有的锁，如果发现多个重名许可则不登录，提供选择，否则找到符合条件的锁直接登录（不建议使用此标志）*/
#define SLM_LOGIN_FLAG_FIND_ALL         0x0001    
/** 许可登录控制：指定许可版本 */
#define SLM_LOGIN_FLAG_VERSION          0x0004
/** 许可登录控制：指定锁号（芯片号）*/
#define SLM_LOGIN_FLAG_LOCKSN           0x0008
/** 许可登录控制：指定服务器 */
#define SLM_LOGIN_FLAG_SERVER           0x0010
/** 许可登录控制：指定碎片代码 */
#define SLM_LOGIN_FLAG_SNIPPET          0x0020


/** 错误码查询返回语言类型ID：简体中文 */
#define LANGUAGE_CHINESE_ASCII                  0x0001
/** 错误码查询返回语言类型ID：英语 */
#define LANGUAGE_ENGLISH_ASCII                  0x0002
/** 错误码查询返回语言类型ID：繁体中文 */
#define LANGUAGE_TRADITIONAL_CHINESE_ASCII      0x0003

/** 初始化时设置，表示将收到 Virbox许可服务 的消息通知 */
#define SLM_INIT_FLAG_NOTIFY            0x01

/** MAC 地址长度 */
#define SLM_MAC_SIZE                    6
/** CPU 信息最大长度 */
#define SLM_MAX_CPU_INFO_SIZE           128
/** BIOS 信息最大长度 */
#define SLM_MAX_BIOS_INFO_SIZE          128
/** Session ID 的最大长度，字符串 */
#define SLM_MAX_SESSION_ID_SIZE         32


/** 许可登录后的内存句柄，不需要客户维护内存，Virbox许可服务 替开发者维护内存，返回一个内存id，范围在0-N之间 */
typedef unsigned int SLM_HANDLE_INDEX; 

/** 获得锁信息类型枚举  */
typedef enum _INFO_TYPE 
{
    /**  硬件锁锁信息  */
    LOCK_INFO = 1,
    /**  访问许可的会话信息 */
    SESSION_INFO = 2,
    /**  当前登录的许可信息 */
    LICENSE_INFO  = 3,
	/**  锁内文件列表 */
	FILE_LIST  = 4
} INFO_TYPE;

/** 许可数据区类型枚举  */ 
typedef enum _LIC_USER_DATA_TYPE 
{
    /** 只读区 */
    ROM = 0,     
    /** 读写区 */
    RAW = 1,
    /** 公开区 */
    PUB = 2
} LIC_USER_DATA_TYPE;

/** 设备描述类型  */ 
typedef enum _ENUM_DESC_TYPE 
{
    ENUM_DESC_LOCAL_DONGLE = 0,
    ENUM_DESC_REMOTE_DONGLE = 1,
    ENUM_DESC_CLOUD = 2,
    ENUM_DESC_SMART_OFFLINE = 3,
    ENUM_DESC_LOCAL_SLOCK = 4,
	ENUM_DESC_REMOTE_SLOCK = 5,
} ENUM_DESV_TYPE;

/** 硬件锁闪灯控制结构 */
typedef struct _ST_LED_CONTROL 
{
    /**  0表示蓝色LED，1表示红色LED，参考宏：LEX_COLOR_XXX  */
    SS_UINT32   index;
    /**  0代表关闭，1代表打开， 2代表闪烁，参考宏：LED_STATE_XXX */
    SS_UINT32   state;
    /**  LED灯闪烁时间间隔（毫秒）*/
    SS_UINT32   interval;   
} ST_LED_CONTROL;

/** 初始化参数   */
typedef struct _ST_INIT_PARAM 
{
    /** 版本－用来兼容，当前使用 SLM_CALLBACK_VERSION02 */
    SS_UINT32       version;
    /** 如果需要接收 Virbox许可服务 通知，填 SLM_INIT_FLAG_NOTIFY */
    SS_UINT32       flag;
    /** 回调函数指针*/
    SS_CALL_BACK    pfn;
    /** 通信连接超时时间（毫秒），如果填0，则使用默认超时时间（7秒）*/
    SS_UINT32       timeout;
    /** API密码，可从 VirboxLM 云开发者中心（https://developer.lm.virbox.com），通过“查看开发商信息”获取 */
    SS_BYTE         password[SLM_DEV_PASSWORD_LENGTH];
} ST_INIT_PARAM;

/** 许可Login 结构 */
typedef struct _ST_LOGIN_PARAM
{ 
    /** 结构体大小（必填）*/
    SS_UINT32       size;
    /** 要登录的许可ID*/
    SS_UINT32       license_id;
    /** 许可会话的超时时间（单位：秒）,填0则使用默认值：600秒   */
    SS_UINT32       timeout;
    /** 许可登录的模式：本地锁，网络锁，云锁，软锁（见SLM_LOGIN_MODE_XXX)，如果填0，则使用SLM_LOGIN_MODE_AUTO*/
    SS_UINT32       login_mode;
    /** 许可登录的标志：见SLM_LOGIN_FLAG_XXX，非特殊用途，不设置此参数 */
    SS_UINT32       login_flag;
    /** 许可登录指定的锁唯一序列号（二进制）（可选）*/
    SS_BYTE         sn[SLM_LOCK_SN_LENGTH];
    /** 网络锁服务器地址（可选），仅识别IP地址 */
    SS_CHAR         server[SLM_MAX_SERVER_NAME];
    /** 云锁用户token（可选）*/
    SS_CHAR         access_token[SLM_MAX_ACCESS_TOKEN_LENGTH];
    /** 云锁服务器地址（可选）*/
    SS_CHAR         cloud_server[SLM_MAX_CLOUD_SERVER_LENGTH];
    /** 碎片代码种子（可选），如果要支持碎片代码,login_flag需要指定为SLM_LOGIN_FLAG_SNIPPET*/
    SS_BYTE         snippet_seed[SLM_SNIPPET_SEED_LENGTH];
    /** 已登录用户的 guid 或本地已绑定的软锁 guid（字符串）（可选） */
    SS_CHAR         user_guid[SLM_CLOUD_MAX_USER_GUID_SIZE];
} ST_LOGIN_PARAM;

/** 锁信息结构  */
typedef struct _ST_LOCK_INFO 
{
    ///  结构体大小
    SS_UINT32           size;      
    ///  设备类型，0 = 普通用户锁；2 = 时钟用户锁
    SS_UINT8            device_type;        
    ///  设备型号, 0 = 精锐5用户锁
    SS_UINT8            device_mode;    
    ///  保留
    SS_UINT16           res;             
    ///  Entry 固件版本（用户不必关心）
    SS_UINT8            lmfirm_version[4];  
    ///  H5 固件版本，可用于判断加密锁固件版本
    SS_UINT32           h5firm_version;   
    ///  硬件版本（用户不必关心）
    SS_UINT32           hardware_version;   
    ///  生产日期（UTC）
    SS_UINT32           manufacture_date;   
    ///  总共空间（单位：字节）
    SS_UINT32           total_space;        
    ///  剩余空间（单位：字节）
    SS_UINT32           available_space;    
    ///  通讯协议（用户不必关心）
    SS_UINT32           protocol;        
    ///  总线地址（用户不必关心）
    SS_UINT32           slave_addr;       
    ///  锁内时钟（UTC）
    SS_UINT32           clock;        
    ///  0 = 虚拟时钟；2 = 硬件时钟
    SS_UINT32           clock_type;    
    ///  时钟锁掉电次数（仅硬件时钟有效，精锐5时钟锁特有）
    SS_UINT32           drop_times;        
    ///  锁芯片序列号，标识唯一性
    SS_BYTE             lock_sn[SLM_LOCK_SN_LENGTH];  
    ///  锁的编码区：用户码区，存储了外壳编号，也可标识唯一性
    SS_BYTE             user_info[128];     
    ///  锁的编码区：内部码区
    SS_BYTE             inner_info[128];    
    ///  0 = 不支持共享；1 = 支持共享
    SS_UINT32           shared_enabled;
    ///  共享锁的所有者（开发商ID）
    SS_BYTE             owner_developer_id[SLM_DEVELOPER_ID_SIZE];
} ST_LOCK_INFO;

/** 会话信息结构体  */
typedef struct _ST_SESSION_INFO 
{
    ///  结果大小
    SS_UINT32           size;            
    ///  已经登录的许可id 
    SS_UINT32           license_id;               
    union
    {
        SS_BYTE         sn[SLM_LOCK_SN_LENGTH];
        SS_BYTE         user_guid[SLM_GUID_LENGTH];
    };
    ///  开发商设置的会话 time_out
    SS_UINT32           app_time_out;        
    ///  当前软件的进程 id
    SS_UINT32           app_process_id;      
    ///  网卡MAC地址
    SS_UINT8            mac[SLM_MAC_SIZE];      
    char                session_id[SLM_MAX_SESSION_ID_SIZE]; 
    ///  CPU ID Verndor 信息
    char                cpuinfo[SLM_MAX_CPU_INFO_SIZE];  
    ///  BIOS信息 主板名称等   
    char                bios[SLM_MAX_BIOS_INFO_SIZE];     
} ST_SESSION_INFO;

/** 许可信息结构  */
typedef struct _ST_SLM_LICENSE_INFO
{
    ///  结构体大小
    SS_UINT32   size;
    ///  许可版本号
    SS_UINT32   lic_ver;  
    ///  许可标志位（注：不要改动flag的偏移）
    SS_BYTE     flag[4];        
    ///  许可的guid
    SS_BYTE     guid[SLM_LOCK_SN_LENGTH];  
    ///  许可ID
    SS_UINT32   lic_id;    
    ///  起始时间
    SS_UINT32   start_time;     
    ///  终止时间
    SS_UINT32   end_time;   
    ///  时间跨度
    SS_UINT32   span_time;    
    ///  升级时间戳
    SS_UINT32   time_stamp;     
    ///  升级流水号
    SS_UINT16   serial;        
    ///  许可最大并发数
    SS_UINT16   concurrency;    
    ///  最大次数限制
    SS_UINT32   count;         
    ///  模块功能标识位
    SS_UINT64   module_bit;    
    ///  锁定时间
    SS_UINT32   lock_time;      
    ///  第一次使用时间
    SS_UINT32   first_use_time; 
    ///  当前剩余次数
    SS_UINT32   curr_count;   
    ///  可离线时间
    SS_UINT32   offline_period; 
    ///  最多可同时使用的机器数量，与机器无关，只与数量有关
    SS_UINT32   bind_node;      
    ///  最多可绑定的机总器数，与机器有关，一旦绑定，永久相关
    SS_UINT32   max_bind_node;  
    ///  读写区大小
    SS_UINT32   raw_size;   
    ///  只读区大小
    SS_UINT32   rom_size;   
    ///  公开区大小
    SS_UINT32   pub_size;   
} ST_SLM_LICENSE_INFO;

/** 文件信息结构  */
typedef struct _ST_FILE_INFO 
{
    /** 标志哪些域有效，仅在设置文件属性中使用              */
    SS_BYTE     validate;                
    /** 文件类型，不能修改                                 */
    SS_BYTE     type;                    
    /** 文件访问权限                                       */
    SS_UINT16   pri;              
    /** 文件大小                                           */
    SS_UINT32   size;                  
    /** 文件修改时间                                       */
    SS_UINT32   time;              
    /** 文件名  当前文件名称长度16字节                     */
    SS_BYTE     name[16];                
} ST_FILE_INFO;

/** 文件信息结构列表  */
typedef struct _ST_FILE_INFO_LIST
{
    /// 当前为1
    SS_UINT32       version;        
    SS_UINT32       count;
    ST_FILE_INFO    info[1];
} ST_FILE_INFO_LIST;

/** 设备信息结构  */
typedef struct _ST_DEV_INFO 
{
    ///	local, remote or cloud.(DESC type)
    SS_UINT16  		    desc_type;      
    ///  LM类型（LM_FIRM_TYPE_XXX)
    SS_UINT16           firm_type;      
    SS_BYTE 	        developer_id[SLM_DEVELOPER_ID_SIZE];
    union 
    {
        struct 
        {
            SS_CHAR         cloud_server[114];
            SS_CHAR         user_token[48];
            // 指定 user_guid 登录指定的云账号时需要将此数据转换为字符串。
            SS_BYTE         user_guid[SLM_GUID_LENGTH];
        } cloud, smart_offline;  //  云锁/智能离线

        struct 
        {
            SS_BYTE         serial[SLM_LOCK_SN_LENGTH];
            SS_CHAR         ip[64];
            SS_UINT16       port;
            SS_CHAR         host_name[SLM_MAX_SERVER_NAME];
            //  reserved    
        } h5;  //  硬件锁

        struct 
        {
            // 指定 user_guid 登录指定的软锁时需要将此数据转换为字符串。
            SS_BYTE         user_guid[SLM_GUID_LENGTH]; 
            SS_CHAR         ip[64];
            SS_UINT16       port;
            //SS_BYTE         reserved[114 - 16 - 32];
            SS_CHAR         host_name[SLM_MAX_SERVER_NAME];
            // reserved for remote slock
            // 许可来源，例如：授权码（SC0009000000595）；借阅码（209-6BU-MGP）。
            SS_CHAR         account_name[64];
        } slock;  //  软锁
    };

} ST_DEV_INFO;

/** 设备描述结构  */
typedef struct _ST_ENUM_DEVICE 
{
    ST_DEV_INFO     dev_info;
    ST_LOCK_INFO    lock_info;
} ST_ENUM_DEVICE;

/** 设备信息列表  */
typedef struct _ST_DEV_INFO_LIST
{
    SS_UINT32       version;        // 当前为1
    SS_UINT32       count;
    ST_ENUM_DEVICE  info[1];
} ST_DEV_INFO_LIST;

/** 许可id列表  */
typedef struct _ST_LICENSE_IDS
{
    SS_UINT32       count;
    SS_UINT32       lic_ids[1];
} ST_LICENSE_IDS;

/** 
*   @defgroup RuntimeAPI  Virbox Runtime 接口说明
*   此文档是 Virbox Runtime 用户运行时库，包含许可访问，许可加密，锁内代码执行等接口
*   @{
*/

#ifdef __cplusplus
extern "C" {
#endif

/*!
*   @brief      Runtime API 初始化函数，调用所有 Runtime API 必须先调用此函数进行初始化
*   @param[in]  pst_init    初始化参数，见 #ST_INIT_PARAM 结构声明
*   @return     成功返回SS_OK，失败返回相应的错误码
*   @remarks    #slm_init 函数是 Virbox Runtime API 的初始化函数，在使用其他 Virbox Runtime API 之前，必须要先调用此函数，
*               初始化函数主要是对 Runtime 环境的初始化，并且启动反调试机制。
*               特别说明：
*                   我们不建议您在编写 Windows 动态链接库代码时，在 DllMain 函数中调用 slm_init 和 slm_cleanup，因为这两个函数会在内部启用和退出线程，
*                   这很有可能会造成您的动态链接库在加载的时候，因为存在系统资源抢占的情况而出现线程死锁，从而造成程序句柄泄漏、卡死或崩溃。
*                   您在 Windows 应用程序中或非 DllMain 函数中使用这两个函数则不存在此问题。另外，非 Windows 操作系统的其他系统（如Linux 系统下的 so 库）
*                   的动态链接库也不存在此问题。
*   @see        ST_INIT_PARAM slm_cleanup
*/
SS_UINT32 SSAPI slm_init(IN ST_INIT_PARAM* pst_init);

/*!
*   @brief      查找许可信息(仅对硬件锁有效)
*   @param[in]  license_id      要查找的许可ID（0--0xFFFFFFFF）
*   @param[in]  format          参数格式，参考 #INFO_FORMAT_TYPE ，目前仅支持 #JSON 和 #STRUCT
*   @param[out] license_desc    许可描述信息的指针，格式由 format 指定，需调用 #slm_free 释放
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    此函数用于查找本地锁和网络锁的许可信息，如果成功，需要调用 #slm_free 释放 license_desc。
*               当 format = #STRUCT 时 license_desc 的内容 参考 #ST_DEV_INFO_LIST
*   @see        INFO_FORMAT_TYPE
*/
SS_UINT32 SSAPI slm_find_license(
    IN  SS_UINT32           license_id,
    IN  INFO_FORMAT_TYPE    format,
    OUT char**              license_desc
    );


/*!
*   @brief      枚举已登录的用户 token
*   @param[out] access_token    默认用户的 token，需调用 #slm_free 释放
*   @return     成功返回 SS_OK，如果 oauth 后台进程未启动，则返回 SS_ERROR_BAD_CONNECT
*   @remarks    如果成功，需要调用 #slm_free 释放 access_token
*/
SS_UINT32 SSAPI slm_get_cloud_token(OUT SS_CHAR** access_token);

/*!
*   @brief      安全登录许可,用 #JSON 传递参数,并且检查时间（是否到期或者是否早于开始时间）、次数、并发数是否归零，
*               如果有计数器，则永久性减少对应的计数器，对于网络锁则临时增加网络并发计数器。
*   @param[in]  license_param 登录许可描述参数，可以用来描述 licenseid，或者指定登录特性等。
*   @param[in]  param_format  许可描述字符串类型，仅支持 #STRUCT（为确保安全，SDK版本号2.1.0.15128之后的许可登录将不再支持 json 登录的方法）
*   @param[out] slm_handle    返回登录之后许可句柄index值,范围在 0-256 之间。
*   @param[out] auth          认证 login 函数返回是否正确，对 login 的返回值加扰，解扰后才能得到真正的返回值，防止黑客通过返回值特征找到许可登录规律。不使用可以填 NULL。
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks
*   - #slm_login 函数详细说明：
*       -# 会自动查找跨锁查找许可句柄。
*       -# 在 Runtime 库里面分配管理内存与进程线程信息。
*       -# 对与调用者需要定期监控会话进程，如果进程死锁或者崩溃，自己释放对应的内存和其它资源。
*       -# LM库属于客户定制自动编译，包含 RSA公钥、认证设备ID、开发商编号等一切认证手段。
*       -# LM后续操作必须都要 login 之后才能有权限操作 比如读写、加解密等操作。
*   - 功能参数说明：
*       - 采用结构体：
*       -# 参考 #ST_LOGIN_PARAM 结构详细描述
*       -# #ST_LOGIN_PARAM::size         参数结构体大小，必填项，必须为传入结构体的大小，否则会返回错误 SS_ERROR_RUNTIME_VERSION
*       -# #ST_LOGIN_PARAM::license_id   许可ID，为32位长整数，取值范围 0-4294967295，必写参数
*       -# #ST_LOGIN_PARAM::login_mode   许可登录模式，分为自动模式，以及本地锁、网络锁、云锁、软锁等组合
*       -# #ST_LOGIN_PARAM::sn           指定登录锁号 为二进制硬件锁芯片号（16字节）。
*       -# #ST_LOGIN_PARAM::access_token 如果登录云锁，则需要指定通过 oauth 认证的 access token
*       -# #ST_LOGIN_PARAM::timeout     指定登录会话超时 单位为秒。如果不填写，默认为600秒，硬件锁、软锁许可默认最小不低于 60s，最大不得超过 12小时（12 * 60 * 60 秒）。
*       -# #ST_LOGIN_PARAM::user_guid    登录用户的 guid，最大长度为 #SLM_CLOUD_MAX_USER_GUID_SIZE。一般不使用 guid
*   @code
*		void test_normal()
*       {
*           SS_UINT32           status = SS_OK;
*           ST_INIT_PARAM       init_param = { SLM_CALLBACK_VERSION02, 0, 0, 20000 };
*           SLM_HANDLE_INDEX    slm_handle = 0;
*           ST_LOGIN_PARAM      login_param = { 0 };
*           
*           // psd是必传参数，每个开发者私有，不可泄露，请从 VirboxLM 云开发者中心获取：https://developer.lm.virbox.com
*           const char          psd[] = { 0xDB, 0x3B, 0x83, 0x8B, 0x2E, 0x4F, 0x08, 0xF5, 0xC9, 0xEF, 0xCD, 0x1A, 0x5D, 0xD1, 0x63, 0x41};
*
*           memcpy(init_param.password, psd, sizeof(init_param.password));  
*
*           status = slm_init(&init_param);
*           if(status != SS_OK)
*           {
*               return ;
*           }
*
*           login_param.license_id = 0;
*           login_param.size = sizeof(ST_LOGIN_PARAM);      // 结构体长度必须赋值为正确的长度，否则会出错
*           login_param.login_mode = SLM_LOGIN_MODE_LOCAL;
*
*           status = slm_login(&login_param, STRUCT, &slm_handle, NULL);
*           if(status != SS_OK)
*           {
*               //todo do: deal error code
*               return ;
*           }
*
*           slm_logout(slm_handle);
*       }
*
*		void test_login_with_auth()
*		{
*			unsigned int sts = SS_OK;
*			ss_auth_xor_t auth = { 0 };
*			int key;
*		
*			typedef struct _ss_auth_xor_t
*			{
*				int size;		// 结构体大小
*				int r[4];		// 随机数数组
*				int g[2];		// 公钥 
*			} ss_auth_xor_t;
*
*			....
*			auth.size = sizeof(ss_auth_xor_t);
*			for (int i = 0; i != 4; ++i)
*				auth[i].r = rand();
*			key = (auth.r[0] + auth.r[1]) ^ (auth.r[2] + auth.r[3]);
*
*			sts = slm_login(&login, STRUCT, &slm_handle, &auth);
*			key = key ^ (auth.g[0] + auth.g[1]);
*			sts = (sts ^ key);
*			....
*		}
*   @endcode
*   @see slm_logout SS_UINT32 INFO_FORMAT_TYPE ST_LOGIN_PARAM
*/
SS_UINT32 SSAPI slm_login(
    IN  const ST_LOGIN_PARAM*  license_param,
    IN  INFO_FORMAT_TYPE       param_format,
    OUT SLM_HANDLE_INDEX *     slm_handle,
    IN OUT void*               auth
    );

/*!
*   @brief      许可登出，并且释放许可句柄等资源
*   @param[in]  slm_handle    许可句柄值，由 #slm_login 得到
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    不再使用许可时，需要调用 #slm_logout 退出登录许可，以免其占用 Runtime 库中的内存和资源。
*               例如，由于 Runtime 库只支持最多256个登录句柄，若只登录许可而不登出许可，一旦超出 256 个登录点将占满所有 Runtime 库中的资源，导致后续的登录失败
*   @see        slm_login
*/
SS_UINT32 SSAPI slm_logout(SLM_HANDLE_INDEX slm_handle);

/*!
*   @brief      保持登录会话心跳，避免变为“僵尸句柄”。
*   @param[in]  slm_handle    许可句柄值
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    僵尸句柄：如果进程死循环或者崩溃，slm_handle 不会自动被释放，造成 Runtime 库中内存和资源浪费
*   @code
*       DWORD WINAPI __stdcall _ThreadKeepalive(void *pVoid)
*       {
*           SLM_HANDLE_INDEX slm_handle = *(SLM_HANDLE_INDEX *)(pVoid);
*           SS_UINT32        status = SS_OK;
*
*           while (1)
*           {
*               status = slm_keep_alive(slm_handle);
*               if(status != SS_OK)
*               {
*                   //todo do: deal error code
*               }
*               Sleep(1000 * 10);      // 十秒钟进行一次心跳连接，保证会话的有效性
*           }
*       }
*       
*       {
*           SS_UINT32           status = SS_OK;
*           SLM_HANDLE_INDEX    slm_handle = 0;
*           ST_LOGIN_PARAM      login_param = { 0 };
*           HANDLE hThread;
*           DWORD  id = 0;
*
*           login_param.license_id = 0;
*           login_param.size = sizeof(ST_LOGIN_PARAM);
*           login_param.login_mode = SLM_LOGIN_MODE_LOCAL;
*           login_param.time_out = 30;    // 设置会话为30秒超时
*
*           status = slm_login(&login_param, STRUCT, &slm_handle, NULL);
*           if(status != SS_OK)
*           {
*               //todo do: deal error code
*               return ;
*           }
*
*           hThread = CreateThread(NULL, 0, _ThreadKeepalive, &slm_handle, 0, &id);
*           if (hThread == NULL)
*           {
*               //todo: deal error
*           }
*       }
*   @endcode
*   @see       slm_login
*/
SS_UINT32 SSAPI slm_keep_alive(SLM_HANDLE_INDEX slm_handle);

/*!
*   @brief      许可加密，相同的许可ID相同的开发者加密结果相同
*   @param[in]  slm_handle   许可句柄值，由 #slm_login 得到
*   @param[in]  inbuffer     加密输入缓冲区,需要 16字节 对齐，最大不能超过 1520个字节。
*   @param[out] outbuffer    加密输出缓冲区,需要 16字节 对齐 
*   @param[in]  len          加密缓冲区大小，为 16 的整数倍。
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    由于硬件锁最大传输字节数有限，因此加解密时一次传入的字节不得超过 1520个字节，若需要加解密的字节数大于此最大限制，
*               可采用截取数据流，循环调用的方式进行加解密，加解密结果不会受到任何影响。            
*   @code
*       {
*           SS_UINT32   status = SS_OK;
*           SS_BYTE     plain[32] = { 0 };  // 加解密使用AES对称加密，明文数据必须16字节对齐
*           SS_BYTE     enc[32] = { 0 };
*           SS_BYTE     dec[32] = { 0 };
*
*           memcpy(data, "test data...", strlen("test data..."));
*
*           status = slm_encrypt(slm_handle, plain, enc, sizeof(enc));
*           if(status != SS_OK)
*           {
*               // todo: deal error code
*               return ;
*           }
*
*           status = slm_decrypt(slm_handle, enc, dec, sizeof(dec));
*           if(status != SS_OK)
*           {
*               // todo: deal error code
*               return ;
*           }
*
*           //对比解密后的数据是否和明文相等
*           //if(plain == dec)
*           //{ 
*           //    SUCCESS;
*           //}
*           //else
*           //{
*           //    FAILURE;
*           //}
*       }
*   @endcode
*   @see        slm_encrypt slm_decrypt slm_login
 */
SS_UINT32 SSAPI slm_encrypt(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  SS_BYTE*            inbuffer,
    OUT SS_BYTE*            outbuffer,
    IN  SS_UINT32           len
    );

/*!
*   @brief      许可解密，相同的许可ID相同的开发者加密结果相同
*   @param[in]  slm_handle   许可句柄值，由 #slm_login 得到
*   @param[in]  inbuffer     解密输入缓冲区,需要 16字节 对齐。最大不能超过 1520个字节。
*   @param[out] outbuffer    解密输出缓冲区,需要 16字节 对齐 
*   @param[in]  len          加密缓冲区大小，为 16 的整数倍。
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    加密方式采用 AES对称加密，密钥在加密锁内（指硬件锁、云锁、软锁，下同）生成，且没有任何机会能出锁，在保证效率的同时，也最大化的加强了安全性。
*               由于硬件锁最大传输字节数有限，因此加解密时一次传入的字节不得超过 1520个字节，若需要加解密的字节数大于此最大限制，可采用截取数据流，循环调用
*               接口的方式进行加解密，加解密结果不会受到任何影响。
*   @code
*       //see slm_encrypt
*   @endcode
*   @see        slm_encrypt slm_login
 */
SS_UINT32 SSAPI slm_decrypt(
    IN  SLM_HANDLE_INDEX    slm_handle, 
    IN  SS_BYTE*            inbuffer, 
    OUT SS_BYTE*            outbuffer, 
    IN  SS_UINT32           len
    );

/*!
*   @brief      获得许可的用户数据区大小
*   @param[in]  slm_handle 许可句柄值，由 #slm_login 得到
*   @param[in]  type       用户数据区类型，类型定义见 LIC_USER_DATA_TYPE
*   @param[out] pmem_size  返回用户数据区大小
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @see        LIC_USER_DATA_TYPE slm_user_data_getsize slm_user_data_read slm_user_data_write
 */
SS_UINT32 SSAPI slm_user_data_getsize(
    IN SLM_HANDLE_INDEX     slm_handle,
    IN LIC_USER_DATA_TYPE   type,
    OUT SS_UINT32*          pmem_size
    );

/*!
*   @brief      读许可数据，可以读取 #PUB #RAW 和 #ROM
*   @param[in]  slm_handle   许可句柄值，由 #slm_login 得到
*   @param[in]  type         用户数据区类型，参考 #LIC_USER_DATA_TYPE
*   @param[out] readbuf      用户数据区读取缓存区
*   @param[in]  offset       读取的用户数据区的数据偏移
*   @param[in]  len          外部使用的存储缓存区大小
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    读数据区最大支持 64k 数据的读取。
*   @code
*       {        
*           SS_UINT32 size = 0;
*           SS_BYTE   *buff = 0;
*           SS_UINT32 status = SS_OK;
*       
*           status = slm_user_data_getsize(slm_handle, ROM, &size);   // 获取只读区数据
*           if (status == SS_OK && size > 0)
*           {
*               buff = (SS_BYTE *)calloc(sizeof(SS_BYTE), size);
*               status = slm_user_data_read(slm_handle, ROM, buff, 0, size);
*               if(status != SS_OK)
*               {
*                   // todo: deal error code
*               }
*               // 可在此处理获取到的只读区数据
*               free(buff);
*               buff = 0;
*           }
*       }
*   @endcode
*   @see        LIC_USER_DATA_TYPE slm_user_data_getsize slm_user_data_read slm_user_data_write
 */
SS_UINT32 SSAPI slm_user_data_read(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  LIC_USER_DATA_TYPE  type,
    OUT SS_BYTE*            readbuf,
    IN  SS_UINT32           offset,
    IN  SS_UINT32           len
    );

/*!
*   @brief      写许可的读写数据区 ,数据区操作之前请先确认锁内读写区的大小，可以使用 #slm_user_data_getsize 获得
*   @param[in]  slm_handle      许可句柄值，由 #slm_login 得到
*   @param[in]  writebuf        要写入的数据内容存区
*   @param[in]  offset          加密锁内数据区的偏移，即锁内数据区的写入位置
*   @param[in]  len             要写入数据的长度（数据最大长度 = min(#slm_user_data_getsize, #SLM_MAX_WRITE_SIZE)
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    仅读写区可以通过应用程序写入数据，因此此接口不需要传入数据区类型，接口会直接将数据写入读写区。
*               数据区写入时，如果数据长度大于 #SLM_MAX_WRITE_SIZE ，需要开发商自行进行分包写入。
*   @code
*       {
*           SS_UINT32 size = 0;
*           SS_BYTE   write[20] = { "write data" };
*           SS_UINT32 status = SS_OK;
*           SS_UINT32 offset = 0
*
*           status = slm_user_data_getsize(slm_handle, RAW, &size);   // 仅读写区可写入数据
*           if (status == SS_OK && size > 0)
*           {
*               size = min( offset + sizeof(write), size);    // 写入数据不得超过获取到的数据长度
*               status = slm_user_data_write(slm_handle, write, offset, size);
*               if(status != SS_OK)
*               {
*                   // todo: deal error code
*               }
*           }
*       }
*   @endcode
*   @see       LIC_USER_DATA_TYPE   slm_user_data_getsize slm_user_data_read slm_user_data_write
 */
SS_UINT32 SSAPI slm_user_data_write(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  SS_BYTE*            writebuf,
    IN  SS_UINT32           offset,
    IN  SS_UINT32           len
    );

/*!
*   @brief      获得指定许可的公开区数据区大小，需要登录 0号许可
*   @param[in]  slm_handle    0号许可句柄值，其他许可句柄无法通过此方式得到公开区大小，由 #slm_login 得到
*   @param[in]  license_id    要获取数据区大小的 许可ID
*   @param[out] pmem_size     返回数据区大小
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    某些情况下，用户希望在不登录许可的情况下，获取到许可的公开区数据，例如许可已经不可用（许可到期、次数用尽等）。
*               此时用户可用通过调用此接口进行获取，前提是需要登录 0号许可，然后将 0号许可 句柄和要查询公开区的 许可ID 传入参数，获取该许可的公开区数据。
*               备注：有关 0号许可 的介绍，可参考《Virbox 许可体系与许可管理》文档中关于 0号许可 的描述
*   @see        slm_user_data_read_pub 
*/
SS_UINT32 SSAPI slm_pub_data_getsize(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  SS_UINT32           license_id,
    OUT SS_UINT32*          pmem_size
    );

/*!
*   @brief      读取许可公开区，需要登录 0号许可
*   @param[in]  slm_handle   0号许可 句柄值，其他许可句柄无法通过此方式得到公开区内容，由 #slm_login 得到
*   @param[in]  license_id   要获取数据区内容的 许可ID
*   @param[out] readbuf      外部存储要读取数据区内容的缓冲区
*   @param[in]  offset       要读取数据区的数据偏移
*   @param[in]  len          外部存储缓冲区大小
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    某些情况下，用户希望在不登录许可的情况下，获取到许可的公开区数据，例如许可已经不可用（许可到期、次数用尽等）。
*               此时用户可用通过调用此接口进行获取，前提是需要登录 0号许可，然后将 0号许可 句柄和要查询公开区的 许可ID 传入参数，获取该许可的公开区数据。
*               备注：有关 0号许可 的介绍，可参考《Virbox 许可体系与许可管理》文档中关于 0号许可 的描述
*   @code
*       {
*           SS_UINT32 size = 0;
*           SS_BYTE   *buff = 0;
*           SS_UINT32 status = SS_OK;
*           SS_UINT32 license_id = 1;   // 需要获取数据区的许可ID
*
*           // 此处需要登录零号许可，请参考 slm_login 的 code 示例
*
*           status = slm_pub_data_getsize(slm_handle, license_id, &size);   // 获取指定许可的公开区内容
*           if (status == SS_OK && size > 0)
*           {
*               buff = (SS_BYTE *)calloc(sizeof(SS_BYTE), size);
*               status = slm_user_data_read(slm_handle, license_id, buff, 0, size);
*               if(status != SS_OK)
*               {
*                   // todo: deal error code
*               }
*               // 可在此处理获取到的数据
*               free(buff);
*               buff = 0;
*           }
*       }
*   @endcode
*   @see        slm_user_data_pub_getsize 
*/
SS_UINT32 SSAPI slm_pub_data_read(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  SS_UINT32           license_id,
    OUT SS_BYTE*            readbuf,
    IN  SS_UINT32           offset,
    IN  SS_UINT32           len
    );

/*!
*   @brief      获取已登录许可的状态信息，例如许可信息、硬件锁信息等
*   @param[in]  slm_handle  许可句柄值，由 #slm_login 得到
*   @param[in]  type        信息类型，参考 #INFO_TYPE
*   @param[in]  format      信息格式，参考 #INFO_FORMAT_TYPE ，当前仅支持 #JSON 和 #STRUCT
*   @param[out] result      返回结果，如果函数返回成功，需要调用 #slm_free 释放
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    通过调用此接口，可以获取当前登录许可的：许可信息、会话信息、硬件锁信息（仅支持硬件锁）、锁内文件列表（仅支持硬件锁）
*   @code
*   // JSON 参数说明：
*   - type = LICENSE_INFO （如果字段不存在，则表示没有该许可限制）
*       {
*           "rom_size" :number(云锁不支持）
*           "raw_size" :number（云锁不支持）
*           "pub_size" :number（云锁不支持）
*           
*           "type": "local"/"remote"/"cloud"
*           "sn":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
*           "guid":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
*           "developer_id":   "xxxxxxxxxxxxxxxx"
*           "license_id":     number
*           "enable":         bool
*           "start_time":     number
*           "end_time":       number
*           "first_use_time": number
*           "span_time":      number
*           "counter":        number
*           "concurrent_type": "process" / "win_user_session"    // 并发类型
*           "concurrent":     number    //并发数
*           "version":        number
*           "module":number
*           "last_update_timestamp":  number
*           "last_update_timesn":     number
*           "lock_time":      number     // 许可被锁定的时间，正常许可不含此字段
*       }
*
*   - type = SESSION_INFO
*       {
*           "app_process_id":  number,
*           "app_time_out":    number,
*           "session_id":      （只支持云锁）
*           "bios": "BIOS information", （云锁不支持）
*           "cpuinfo": "CPU name", （云锁不支持）
*           "sn": ""(HEX16 String), （只支持硬件锁）
*           "user_guid": ""(HEX16 String) （只支持软锁）
*           "mac":"00-00-00-00-00-00" （云锁不支持）
*       }
*    
*   - type = LOCK_INFO （云锁不支持）
*       {
*           "avaliable_space": number(Bytes),
*           "communication_protocol": number,
*           "lock_firmware_version": "0.0.0.0",
*           "lm_firmware_version": "1.1.1.1",
*           "h5_device_type": number,
*           "hardware_version": "2.2.2.2",
*           "manufacture_date": "2000-01-01 00:00:00",
*           "lock_sn": ""(HEX16 String),
*           "slave_addr": number,
*           "clock": number(UTC Time),
*           "user_info": ""(HEX16 String)(128字节)
*           "inner_info": ""(HEX16 String)(128字节）
*       }
*   
*   - type = FILE_LIST
*       [
*        {
*           "validate":0,       (标志哪些域有效，不必关心)
*           "type":0,           (文件类型。二进制文件=0；可执行文件(evx)=1；密钥文件=2)
*           "privilege":0,      (文件访问权限，最大权限为 0xFF)
*           "size":123,         (文件大小，单位：字节)
*           "time":12345678,    (文件创建时间，UTC时间秒)
*           "name":"file1.evx"  (文件名称)
*        },
*        {...}
*       ]
*
*   // STRUCT 参数说明
*   - type = LICENSE_INFO
*      result 参考结构 ST_SLM_LICENSE_INFO
*   - type = SESSION_INFO
*       result 参考结构 ST_SESSION_INFO
*   - type = LOCK_INFO
*       result 参考结构 ST_LOCK_INFO
*   - type = FILE_LIST
*       result 参考结构 ST_FILE_INFO_LIST
*   @endcode
*   @see INFO_TYPE INFO_FORMAT_TYPE SLM_HANDLE_INDEX slm_login
*/
SS_UINT32 SSAPI slm_get_info(
    IN  SLM_HANDLE_INDEX	slm_handle,
    IN  INFO_TYPE			type,
    IN  INFO_FORMAT_TYPE	format,
    OUT char**              result
    );

/*!
*   @brief      开发者自定义算法，锁内可执行算法，锁内静态代码执行（仅支持硬件锁），
*               由开发者调用 \link D2CAPI \endlink 库中的 #d2c_add_pkg 签发可执行代码接口生成，提前将可执行算法下载到锁内
*   @param[in]  slm_handle  许可句柄值，由 #slm_login 得到
*   @param[in]  exfname     锁内可执行算法的文件名
*   @param[in]  inbuf       要传给锁内可执行算法的数据，输入缓冲区
*   @param[in]  insize      输入数据长度(最大支持缓冲区大小参考宏： #SLM_MAX_INPUT_SIZE )
*   @param[out] poutbuf     锁内可执行算法的返回数据，输出缓存区
*   @param[in]  outsize     输出缓存长度
*   @param[out] pretsize    实际返回缓存长度(最大支持缓冲区大小参考宏： #SLM_MAX_OUTPUT_SIZE )
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    软件开发商可以从 APP 软件端移植关键代码到锁内，这个过程跟传统 精锐4 与 精锐5 没有太大的区别。（移植代码相关理念对于精锐系列的老客户可以跳过，开发商可以把真正的行业代码或者加密算法移植，并且在锁内执行）。
*               区别在于需要跟许可绑定。
*
*               许可绑定的好处：
*               -# 客户不需要自己写代码来判断授权情况。
*               -# 移植的代码可以结合灵活的许可授权，透明的使用限时或限次失效，管理及其方便。
*               -# 当许可失效之后，该算法不可执行，并且整个过程都在锁内判断，非常安全。
*
*   @code
*       {
*           SS_BYTE inbuff[MAX_BUFFER_SIZE] = { 0 };
*           SS_BYTE outbuff[MAX_BUFFER_SIZE] = { 0 };
*           char    *dongle_exe = "dongle.evx"          // 锁内可执行程序文件名
*           SS_UINT32 retlen = 0;
*           SS_UINT32 status = 0;
*
*           memcpy(inbuff, "1234567890", 10);
*
*           status = slm_execute_static(slm_handle, dongle_exe, inbuff, 10, outbuff, MAX_BUFFER_SIZE, &retlen);
*           if(status != SS_OK)
*           {
*               //todo do: deal error code
*               return ;
*           }
*           // todo: 处理锁内程序的返回数据
*       }
*   @endcode
*   @see        slm_login slm_execute_dynamic slm_snippet_execute
*/
SS_UINT32 SSAPI slm_execute_static(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  const char*         exfname,
    IN  SS_BYTE*            inbuf,
    IN  SS_UINT32           insize,
    OUT SS_BYTE*            poutbuf,
    IN  SS_UINT32           outsize,
    OUT SS_UINT32*          pretsize
    );

/*!
*   @brief      开发者自定义算法，锁内可执行算法，锁内动态执行代码（仅支持硬件锁），在应用程序运行过程中下载到锁内进行执行
*   @param[in]  slm_handle  许可句柄值，由 #slm_login 得到
*   @param[in]  exf_buffer  动态exf 算法缓冲区，由开发者调用 \link D2CAPI \endlink 库中的 #gen_dynamic_code 接口生成的 D2C数据
*   @param[in]  exf_size    动态exf 文件大小
*   @param[in]  inbuf       要传给锁内可执行算法的数据，输入缓冲区
*   @param[in]  insize      输入数据长度(最大支持缓冲区大小参考宏： #SLM_MAX_INPUT_SIZE )
*   @param[out] poutbuf     锁内可执行算法的返回数据，输出缓存区
*   @param[in]  outsize     输出缓存长度
*   @param[out] pretsize    实际返回缓存长度(最大支持缓冲区大小参考宏： #SLM_MAX_OUTPUT_SIZE )
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    区别于 #slm_execute_static 锁内静态代码执行。锁内静态代码执行，是在初始化硬件锁时，通过签发文件将可执行代码下载到锁内，代码永久保存在锁内。
*               而 #slm_execute_dynamic 锁内动态代码执行，是提前通过 \link D2CAPI \endlink 签好可执行代码包，随应用程序一起，当需要执行时下载到锁内，执行完成后锁内会删除此程序，不在锁内长时间保留。
*   @code
*       {
*           SS_BYTE     exf_buff[MAX_BUFFER_SIZE] = { 0 };       // 动态代码升级包缓冲区
*           SS_UINT32   exf_size = 0;                            // 动态代码升级包大小
*           SS_BYTE     inbuff[MAX_BUFFER_SIZE] = { 0 };
*           SS_BYTE     outbuff[MAX_BUFFER_SIZE] = { 0 };
*           SS_UINT32   retlen = 0;
*           SS_UINT32   status = 0;
*
*           // 1、给动态代码缓冲区赋值。
*           // {...}
*
*           memcpy(inbuff, "1234567890", 10);
*
*           status = slm_execute_static(slm_handle, exf_buff, exf_size, inbuff, 10, outbuff, MAX_BUFFER_SIZE, &retlen);
*           if(status != SS_OK)
*           {
*               //todo do: deal error code
*               return ;
*           }
*           // todo: 处理锁内程序的返回数据
*       }
*   @endcode
*   @see        slm_login slm_execute_static slm_snippet_execute
*/
SS_UINT32 SSAPI slm_execute_dynamic(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  SS_BYTE*            exf_buffer,
    IN  SS_UINT32           exf_size,
    IN  SS_BYTE*            inbuf,
    IN  SS_UINT32           insize,
    OUT SS_BYTE*            poutbuf,
    IN  SS_UINT32           outsize,
    OUT SS_UINT32*          pretsize
    );

/*!
*   @brief      Virbox许可服务 内存托管内存申请
*   @param[in]  slm_handle   许可句柄值，由 #slm_login 得到
*   @param[in]  size         申请内存大小，最大 #SLM_MEM_MAX_SIZE 。
*   @param[out] mem_id       返回托管内存id
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    Virbox许可服务 的托管内存原理是 APP 利用有效的许可作为凭证，在 Virbox许可服务 模块内数据加密且数据校验，其内存二进制数据没有明文，
*               并且无法非法修改,黑客极难查看与篡改使用。
*
*               用户可以把自己 APP 的一些敏感数据保存到 Virbox许可服务 的托管内存，比如帐号口令，数据库的帐号与密码，涉及到操作权限的临时数据放到 Virbox许可服务 内存托管里面。
*               另外一方面 APP 跟 Virbox许可服务 耦合度极大的提高，防止黑客脱离 Virbox许可服务 调试与运行。
*
*               内存托管的好处：
*               -# 敏感数据内存不泄密、无法篡改。
*               -# 可以跨线程安全交互数据。
*               -# APP软件、许可、Virbox许可服务 三者强耦合，软件防止被破解能力极高。（黑客需要手工剥离和重建才能使用软件）
*
*               说明：托管内存每次申请的最大内存为 #SLM_MEM_MAX_SIZE ，每个内存通过一个 mem_id 标识。可申请的内存总大小为 256kb。
*
*   @code
*       {
*           SS_UINT32 status = SS_OK;
*           SS_UINT32 mem_index = 0;
*           SS_UINT32 mem_size = 1024;
*           SS_BYTE   data[] = "test data....";
*           SS_BYTE   read[100] = { 0 };
*           SS_UINT32 write_len = 0;
*           SS_UINT32 read_len = 0;
*
*           status = slm_mem_alloc(slm_handle, mem_size, &mem_index);
*           if(status != SS_OK)
*           {
*               //todo do: deal error code
*               return ;
*           }
*           status = slm_mem_write(slm_handle, mem_index, 0, strlen((char *)data), data, &write_len);
*           if(status != SS_OK)
*           {
*               //todo do: deal error code
*               return ;
*           }
*           status = slm_mem_read(slm_handle, mem_index, 0, write_len, read, &read_len);
*           if(status != SS_OK)
*           {
*               //todo do: deal error code
*               return ;
*           }
*           //对比原始数据和读取到的数据是否相等
*           //if(data == read)
*           //{
*           //    SUCCESS;
*           //}
*           //else
*           //{
*           //    FAILURE;
*           //}

*           status = slm_mem_free(slm_handle, mem_index);
*       }
*   @endcode
*   @see        slm_mem_free slm_mem_read slm_mem_write
*/
SS_UINT32 SSAPI slm_mem_alloc(
    IN  SLM_HANDLE_INDEX    slm_handle, 
    IN  SS_UINT32           size, 
    OUT SS_UINT32*          mem_id
    );

/*!
*   @brief     释放托管内存
*   @param[in] slm_handle    许可句柄值，由 #slm_login 得到
*   @param[in] mem_id        托管内存id
*   @return    成功返回 SS_OK，失败返回相应的错误码
*   @remarks
*   @code
*       //see slm_mem_alloc
*   @endcode
*   @see       slm_mem_alloc slm_mem_free slm_mem_read slm_mem_write
*/
SS_UINT32 SSAPI slm_mem_free(
    IN  SLM_HANDLE_INDEX    slm_handle, 
    IN  SS_UINT32           mem_id
    );

/*!
*   @brief      Virbox许可服务 内存托管读
*   @param[in]  slm_handle    许可句柄值，由 #slm_login 得到
*   @param[in]  mem_id        托管内存id
*   @param[in]  offset        读取托管数据偏移
*   @param[in]  len           读取托管数据长度
*   @param[out] readbuff      外部存储托管数据缓存
*   @param[out] readlen       返回实际读取长度
*   @return    成功返回 SS_OK，失败返回相应的错误码
*   @remarks
*   @code
*       //see slm_mem_alloc
*   @endcode
*   @see slm_mem_alloc slm_mem_free slm_mem_write
*/
SS_UINT32 SSAPI slm_mem_read(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  SS_UINT32           mem_id,
    IN  SS_UINT32           offset,
    IN  SS_UINT32           len,
    IN  SS_BYTE*            readbuff,
    OUT SS_UINT32*          readlen
    );

/*!
*   @brief      Virbox许可服务 内存托管内存写入
*   @param[in]  slm_handle    许可句柄值，由 #slm_login 得到
*   @param[in]  mem_id        托管内存id
*   @param[in]  offset        托管数据偏移
*   @param[in]  len           写入的托管数据长度
*   @param[in]  writebuff     需要写入托管内存区域的数据缓存
*   @param[out] numberofbyteswritten 返回实际写的长度
*   @return     成功返回 SS_OK，失败则返回相应的错误码
*   @remarks
*   @code
*       //see slm_mem_alloc
*   @endcode
*   @see slm_mem_alloc slm_mem_free slm_mem_read
*/
SS_UINT32 SSAPI slm_mem_write(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  SS_UINT32           mem_id,
    IN  SS_UINT32           offset,
    IN  SS_UINT32           len,
    IN  SS_BYTE*            writebuff,
    OUT SS_UINT32*          numberofbyteswritten
    );

/*!
*   @brief      检测是否正在调试
*   @param[in]  auth     验证数据(保留参数，填 NULL 即可）
*   @return     SS_UINT32 错误码, 返回 SS_OK 代表未调试
*   @remarks     必须调用 #slm_init 之后才可使用，否则有可能会造成程序崩溃
*   @see        slm_init
*/
SS_UINT32 SSAPI slm_is_debug(IN void *auth);

/*!
*   @brief      通过证书类型，获取已登录许可的设备证书
*   @param[in]  slm_handle  许可句柄，由 #slm_login 得到
*   @param[in]  cert_type   证书类型，参考 #CERT_TYPE
*   @param[out] cert        证书缓冲区
*   @param[in]  cert_size   缓冲区大小
*   @param[out] cert_len    返回的设备证书大小
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    获取设备证书，此处的设备指硬件锁、云锁。
*               如果 cert_type = #CERT_TYPE_DEVICE_CERT，其功能与 #slm_get_device_cert 完全一致；
*               如果为其他类型，则仅支持硬件锁。
*               通过此接口可以获取加密锁的根证书、设备子CA 和设备，方便合成设备证书链。
*   @see    slm_login slm_get_device_cert
*/
SS_UINT32 SSAPI slm_get_cert(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  CERT_TYPE           cert_type,
    OUT SS_BYTE*            cert,
    IN  SS_UINT32           cert_size,
    OUT SS_UINT32*          cert_len
    );

/*!
*   @brief      获取已登录的加密锁证书
*   @param[in]  slm_handle  许可句柄，由 #slm_login 得到
*   @param[out] device_cert 设备证书缓冲区
*   @param[in]  buff_size   缓冲区大小
*   @param[out] return_size 返回的设备证书大小
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    获取已登录的加密锁证书，此处的加密锁指硬件锁、云锁、软锁
*   @see        slm_login
*/
SS_UINT32 SSAPI slm_get_device_cert(
    IN  SLM_HANDLE_INDEX    slm_handle,
    OUT SS_BYTE*            device_cert,
    IN  SS_UINT32           buff_size,
    OUT SS_UINT32*          return_size
    );

/*!
*   @brief      设备正版验证（仅支持硬件锁）
*   @param[in]  slm_handle          许可句柄，由 #slm_login 得到
*   @param[in]  verify_data         验证数据（必须以字符"SENSELOCK"(9字节)开头）
*   @param[in]  verify_data_size    验证数据大小，大小必须为 #SLM_VERIFY_DATA_SIZE (41)个字节
*   @param[out] signature           返回的签名结果
*   @param[in]  signature_buf_size  缓冲区大小
*   @param[out] signature_size      签名结果大小
*   @return     成功返回 SS_OK，失败返回相应的错误码
*   @remarks    锁内使用设备私钥签名，需要用硬件锁证书公钥验签
*   @code
*       {
*           SS_UINT32       status = SS_OK;
*           SS_BYTE         verify_data[41] = {0};
*           SS_BYTE         my_data[32] = {"verify data..."};
*           const SS_BYTE   header[9] = {"SENSELOCK"};
*           SS_BYTE         signature[2048] = {0};
*           SS_UINT32       signature_size = 0;
*       
*           memcpy(verify_data, header, sizeof(header));
*           memcpy(verify_data + sizeof(header), my_data, sizeof(my_data));
*           
*           status = slm_sign_by_device(slm_handle, verify_data, sizeof(verify_data), signature, sizeof(signature), &signature_size);
*           if(status != SS_OK)
*           {
*               // todo: deal error code
*           }
*       }
*   @endcode
*   @see        slm_login
*/
SS_UINT32 SSAPI slm_sign_by_device(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  SS_BYTE*            verify_data,
    IN  SS_UINT32           verify_data_size,
    OUT SS_BYTE*            signature,
    IN  SS_UINT32           signature_buf_size,
    OUT SS_UINT32*          signature_size
    );

/*!
*   @brief         获取时间修复数据，用于生成时钟校准请求
*   @param[in]     slm_handle  许可句柄，由 #slm_login 得到
*   @param[out]    rand        随机数
*   @param[out]    lock_time   锁时间
*   @param[in,out] pc_time     PC时间，返回的PC时间（传入0则取当时时间）
*   @return        成功返回 SS_OK ，失败则返回相应错误码
*/
SS_UINT32 SSAPI slm_adjust_time_request(
    IN  SLM_HANDLE_INDEX    slm_handle,
    OUT SS_BYTE             rand[SLM_FIXTIME_RAND_LENGTH],
    OUT SS_UINT32*          lock_time,
    IN OUT SS_UINT32*       pc_time
    );

/*!
*   @brief      闪烁指示灯
*   @param[in]  slm_handle      许可句柄，由 #slm_login 得到
*   @param[in]  led_ctrl        闪灯控制结构( #ST_LED_CONTROL )
*   @return     成功返回 SS_OK ，失败返回相应的错误码
*   @remarks
*   @code
*       {
*           ST_LED_CONTROL led = { 0 };
*           SS_UINT32 status = SS_OK;
*    
*           led.index = 0;         //  0表示蓝色LED，1表示红色LED  
*           led.state = 2;         //  0代表关闭，1代表打开， 2代表闪烁 
*           led.interval = 1000;   //  闪烁间隔（毫秒）
*
*           status = slm_led_control(slm_handle, &led);
*           if(status != SS_OK)
*           {
*               // todo: deal error code
*           }
*       }
*   @endcode
*   @see        slm_login ST_LED_CONTROL
*/
SS_UINT32 SSAPI slm_led_control(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  ST_LED_CONTROL*     led_ctrl
    );

/*!
*   @brief      获得 Runtime 库 和 Virbox许可服务 的版本信息.
*   @param[out] api_version  API的版本（总是成功）
*   @param[out] ss_version   Virbox许可服务 的版本
*   @return     成功返回 SS_OK ，失败则返回相应的错误码
*/
SS_UINT32 SSAPI slm_get_version(
    OUT SS_UINT32*      api_version, 
    OUT SS_UINT32*      ss_version
    );

/*!
*   @brief     释放API内分配堆区域
*   @param[in] buffer API 生成的堆
*/
void SSAPI slm_free(
    IN void*        buffer
    );

/*!
*   @brief      升级硬件锁许可，D2C包 由 @link D2CAPI @endlink 或 VirboxLM 开发者中心 生成
*   @param[in]  d2c_pkg     d2c文件数据
*   @param[out] error_msg   错误信息，需要调用 #slm_free 释放
*   @return     成功返回 SS_OK ，失败返回错误码
*   @remarks:   D2C包内可能包含多条数据，因此返回的错误码信息也是 json 数组结构，需要分别解析。
*               说明：当前接口仅支持硬件锁许可升级，若需要升级软许可，请调用 #slm_update_ex 接口
*   @code
*     [
*       {"pkg_order":1, "pkg_desc":"package decription.", "status": 0},
*       {"pkg_order":2, "pkg_desc":"package decription.", "status": 0}
*     ]
*   @endcode
*/
SS_UINT32 SSAPI slm_update(
    IN  char*       d2c_pkg, 
    OUT char**      error_msg
    );

/*!
*   @brief      升级由开发锁或 VirboxLM 开发者中心 签发的硬件锁、软锁许可
*   @param[in]  lock_sn     硬件加密锁的锁号（唯一序列号,十六进制字符串格式），可选
*   @param[in]  d2c_pkg     d2c文件数据，必填
*   @param[out] error_msg   错误信息，不使用需要调用 #slm_free 释放
*   @return     成功返回 SS_OK ，失败返回错误码
*   @remarks: 
*           - 此接口支持硬件锁和软锁许可数据的升级
*           - 当升级包为硬件锁许可时，可以指定 lock_sn，提高升级效率，也可不填写；当升级包为软许可时，lock_sn 的值将不被处理
*           - 当升级包为硬件锁许可时，D2C包内可能包含多条数据，每条升级包的错误信息将以 json 结构形式通过 error_msg 返回，需要分别解析
*           - 当升级包为软锁许可时，错误码将直接以返回值形式返回，error_msg 将不被处理
*   @code
*     error_msg 结构：
*     [
*       {"pkg_order":1, "pkg_desc":"package decription.", "status": 0},
*       {"pkg_order":2, "pkg_desc":"package decription.", "status": 0}
*     ]
*   @endcode
*   @see    slm_update
*/
SS_UINT32 SSAPI slm_update_ex(
    IN SS_BYTE*     lock_sn, 
    IN char*        d2c_pkg, 
    OUT char**      error_msg
    );

/*!
*   @brief      锁内短码升级，需指定加密锁唯一序列号，需锁内可执行算法配合（仅支持硬件锁）
*   @param[in]  lock_sn     锁号（唯一序列号,十六进制字符串）
*   @param[in]  inside_file 锁内短码文件名
*   @return     成功返回 SS_OK ，失败返回错误码
*   @remarks    Virbox 提供的通过短码激活功能在硬件锁内生成一条 Virbox许可，该功能需要通过可执行算法的配合，简单的步骤描述为：
*               第一步、在锁内下载支持短码激活的使能文件 slac_enable.evd，文件内容任意，大小最好不超过 256字节；
*               第二步、编写锁内可执行算法，调用深思提供的 h5ses.lib 和 h5ses_lm.lib 库，实现短码转换的过程；
*               第三步、通过执行锁内可执行算法，即调用 #slm_execute_static ， 并传入短码内容，促使锁内可执行算法在锁内将短码转化为
*                       硬件锁可识别的中间文件（文件名开发者设定）。
*               第四步、通过调用 #slm_d2c_update_inside 接口，将锁内生成的中间文件转化为正式的 Virbox许可。
*
*               特别说明：短码激活方案使用较为复杂，需要写锁内代码的技术要求，若开发者需要使用此功能，可联系深思技术服务进行支持。
*   @code
*       {
*           SS_UINT32 status = SS_OK;
*           SS_BYTE   data_buf[1024] = { 0 };
*           SS_UINT32 data_size = 0;
*           char *sn = "9733c80100070205106100030015000c";
*
*           memcpy(data_buf, "1234567890", 10);
*
*           status = slm_execute_static(slm_handle, "test.evx", NULL, 0, data_buf, 10, &data_size);
*           if(status != SS_OK)
*           {
*               // todo: deal error code
*           }
*
*           status = slm_d2c_update_inside(sn, "test.evd");
*           if(status != SS_OK)
*           {
*               // todo: deal error code
*           }
*       }
*   @endcode
*   @see    slm_execute_static
*/
SS_UINT32 SSAPI slm_d2c_update_inside(
    IN char*        lock_sn,
    IN char*        inside_file
    );

/*!
*   @brief       枚举本地锁信息
*   @param[out]  device_info    设备描述信息，不再使用时，需调用 #slm_free 释放
*   @return      成功返回 SS_OK ，失败返回相应错误码
*   @remarks     此接口可以枚举到本地锁的设备信息，此处的设备信息内容可参考 #slm_get_info #LOCK_INFO 中的结构内容
*   @code
*       // 参考 slm_get_license_info 的示例代码
*   @endcode
*   @see slm_enum_device slm_enum_license_id slm_get_license_info
*/
SS_UINT32 SSAPI slm_enum_device(
    OUT char**  device_info
    );

/*!
*   @brief       枚举本地锁信息，支持按返回值类型获取
*   @param[in]   format         信息格式，参考 #INFO_FORMAT_TYPE ，当前仅支持 #JSON 和 #STRUCT
*   @param[out]  device_info    设备描述信息，不再使用时，需调用 #slm_free 释放
*   @return      成功返回 SS_OK ，失败返回相应错误码
*   @remarks     此接口可以枚举到本地锁的设备信息，此处的设备信息内容可参考 #slm_get_info #LOCK_INFO 中的结构内容
*   @code
*       // format = JSON
*           device_info 内容和 slm_enum_device 返回内容一致， 参考 slm_get_license_info 的示例代码
*       // format = STRUCT
            device_info 内容参考 ST_DEV_INFO_LIST，参考 slm_get_license_info_ex 示例代码
*   @endcode
*   @see slm_enum_device slm_enum_license_id slm_get_license_info
*/
SS_UINT32 SSAPI slm_enum_device_ex(
    IN  INFO_FORMAT_TYPE    format,
    OUT void                **device_info
    );

/*!
*   @brief       枚举指定设备下所有许可ID
*   @param[in]   device_info   指定某个锁登陆
*   @param[out]  license_ids   返回所有许可的ID数组，#JSON 格式，需要调用 #slm_free 释放 license_ids
*   @return      成功返回 SS_OK ，失败返回相应错误码
*   @remarks     从 #slm_enum_device 获取到当前设备信息，通过设备信息获取许可信息，主要实现不用登录许可，便可查看许可内容的功能
*   @code
*       // 参考 slm_get_license_info 示例代码
*   @endcode
*   @see slm_enum_device slm_enum_license_id slm_get_license_info
*/
SS_UINT32 SSAPI slm_enum_license_id(
    IN const char   *device_info,
    OUT char        **license_ids
    );

/*!
*   @brief       枚举指定设备下所有许可ID，支持按返回值类型获取
*   @param[in]   device_info    指定某个锁信息
*   @param[in]   format         信息格式，参考 #INFO_FORMAT_TYPE ，当前仅支持 #JSON 和 #STRUCT
*   @param[out]  license_ids    返回所有许可的ID数组，JSON格式，需要调用 #slm_free 释放 license_ids
*   @return      成功返回SS_OK，失败返回相应错误码
*   @remarks     从 #slm_enum_device 获取到当前设备信息，通过设备信息获取许可信息，主要实现不用登录许可，便可查看许可内容的功能
*   @code
*       //  参考 slm_get_license_info_ex 示例代码
*   @endcode
*   @see slm_enum_device slm_enum_license_id slm_get_license_info
*/
SS_UINT32 SSAPI slm_enum_license_id_ex(
    IN  ST_DEV_INFO         *device_info,
    IN  INFO_FORMAT_TYPE    format,
    OUT void                **license_ids
    );

/*!
*   @brief       获取指定设备下指定许可的全部信息
*   @param[in]   device_info    指定某个锁登陆
*   @param[in]   license_id     指定许可ID
*   @param[out]  license_info   返回许可的信息 #JSON 格式 等同于 #slm_get_info 的 #LICENSE_INFO
*   @return      成功返回 SS_OK ，失败返回相应错误码
*   @remarks     获取到指定设备的 许可ID 列表，方便统计锁内许可总数
*   @code
*       {
*           char        *lic_id = NULL;
*           char        *dev_desc = NULL;
*           char        *lic_info = NULL;
*           SS_UINT32   status = SS_OK;
*           Json::Reader reader;      // 此处选择jsoncpp处理json数据
*           Json::Value  root;
*           Json::Value  lic;
*
*           status = slm_enum_device(&dev_desc);    // 首先要先遍历所有设备
*           if ( status == SS_OK && dev_desc != NULL && reader.parse(dev_desc, root))
*           {
*               for (int i = 0; i < root.size(); i++)
*               {
*                   status = slm_enum_license_id(root[i].toStyledString().c_str(), &lic_id);    // 其次获取每个设备的许可ID
*                   if (status == SS_OK && lic_id != NULL)
*                   {
*                       printf(lic_id);
*                       printf("\n");
*
*                       if (reader.parse(lic_id, lic))
*                       {
*                           for (int j = 0; j < lic.size(); j++)
*                           {
*                               status = slm_get_license_info(root[i].toStyledString().c_str(), lic[j].asInt(), &lic_info);  // 最后获取许可的详细信息
*                               if (lic_info)
*                               {
*                                   printf(lic_info);
*                                   printf("\n");
*                                   slm_free(lic_info);
*                                   lic_info = NULL;
*                               }
*                           }
*                       }
*                       slm_free(lic_id);
*                       lic_id = NULL;
*                   }
*               }
*               slm_free(dev_desc);
*               dev_desc = NULL;
*           }
*       }
*   @endcode
*   @see slm_enum_device slm_enum_license_id slm_get_license_info
*/
SS_UINT32 SSAPI slm_get_license_info(
    IN const char   *device_info,
    IN SS_UINT32    license_id,
    OUT char        **license_info
    );

/*!
*   @brief       获取指定设备下指定许可的全部信息，支持按返回值类型获取
*   @param[in]   device_info    指定某个锁登陆
*   @param[in]   format         信息格式，参考 #INFO_FORMAT_TYPE ，当前仅支持 #JSON 和 #STRUCT
*   @param[in]   license_id     指定许可ID
*   @param[out]  license_info   返回许可的信息 #JSON 格式 等同于 #slm_get_info 的 #LICENSE_INFO
*   @return      成功返回 SS_OK，失败返回相应错误码
*   @remarks     获取到指定设备的许可ID列表，方便统计锁内许可总数
*   @code
*       {
*           void        *dev_desc = NULL;
*           SS_UINT32   dev_count = 0;
*           void        *lic_desc = NULL;
*           void         *lic_info = NULL;
*           int         status = SS_OK;
*           
*           status = slm_enum_device_ex(STRUCT, &dev_desc);
*           
*           if (status == SS_OK && dev_desc != NULL)
*           {
*               ST_DEV_INFO_LIST *dl = (ST_DEV_INFO_LIST*)dev_desc;
*               //printf("DEV LIST COUNT:%d\n", dl->count);
*               for (int i = 0; i != dl->count; ++i)
*               {
*                   status = slm_enum_license_id_ex(&dl->info[i].dev_info, STRUCT, &lic_desc);
*                   if (status == SS_OK && lic_desc != NULL)
*                   {
*                       ST_LICENSE_IDS  *lic = (ST_LICENSE_IDS*)lic_desc;
*                       //printf("License Count : %d\n", lic->count);
*                       for (int j = 0; j != lic->count; ++j)
*                       {
*                           status = slm_get_license_info_ex(&dl->info[i].dev_info, lic->lic_ids[j], STRUCT, &lic_info);
*                           if (status == SS_OK && lic_info != NULL)
*                           {
*                               //printf("LicenseID = %d; first use time = %d\n", ((ST_SLM_LICENSE_INFO*)lic_info)->lic_id, ((ST_SLM_LICENSE_INFO*)lic_info)->first_use_time);
*                               slm_free(lic_info);
*                               lic_info = NULL;
*                           }
*                       }
*                       slm_free(lic_desc);
*                       lic_desc = NULL;
*                   }
*               }
*               slm_free(dev_desc);
*               dev_desc = NULL;
*           }
*       }
*   @endcode
*   @see slm_enum_device slm_enum_license_id slm_get_license_info
*/
SS_UINT32 SSAPI slm_get_license_info_ex(
    IN  ST_DEV_INFO          *device_info,
    IN  SS_UINT32           license_id,
    IN  INFO_FORMAT_TYPE    format,
    OUT void                **license_info
    );

/*!
*   @brief     检查模块
*   @param[in] slm_handle     许可句柄，由 #slm_login 得到
*   @param[in] module_id      模块ID，范围由（1 ~ 64）
*   @return    模块存在返回 SS_OK ，不存在返回 SS_ERROR_LICENSE_MODULE_NOT_EXISTS , 否则返回其它错误码
*/
SS_UINT32 SSAPI slm_check_module(IN SLM_HANDLE_INDEX slm_handle, IN SS_UINT32 module_id);

/*!
*   @brief      碎片代码执行（开发者不必关心）
*   @param[in]  slm_handle      许可句柄
*   @param[in]  snippet_code    碎片代码
*   @param[in]  code_size       碎片代码大小
*   @param[in]  input           输入数据
*   @param[in]  input_size      输入数据长度
*   @param[out] output          输出缓冲区
*   @param[in]  outbuf_size     输出缓冲区长度
*   @param[out] output_size     输出数据长度
*   @return     成功返回SS_OK，失败返回相应的错误码
*   @see        slm_login slm_execute_static slm_execute_dynamic
*/
SS_UINT32 SSAPI slm_snippet_execute(
    IN  SLM_HANDLE_INDEX    slm_handle,
    IN  SS_BYTE*            snippet_code,
    IN  SS_UINT32           code_size,
    IN  SS_BYTE*            input, 
    IN  SS_UINT32           input_size, 
    OUT SS_BYTE*            output, 
    IN  SS_UINT32           outbuf_size, 
    OUT SS_UINT32*          output_size
    );

/*!
*   @brief      获取 Runtime 库对应的开发商ID
*   @param[out] developer_id          输出开发商ID，二进制数组
*   @return     成功返回 SS_OK ，失败返回相应错误码
*   @remarks    如果 developer_id 的缓冲区小于 #SLM_DEVELOPER_ID_SIZE ，则势必会造成淹栈的情况
*/
SS_UINT32 SSAPI slm_get_developer_id(OUT SS_BYTE developer_id[SLM_DEVELOPER_ID_SIZE]);

/*!
*  @brief      使用已登录的云许可进行签名（仅支持云锁）
*  @param[in]  slm_handle       许可句柄，由 #slm_login 得到
*  @param[in]  sign_data        要签名的数据（最少16字节，最大64字节）
*  @param[in]  sign_length      要签名的数据长度
*  @param[out] signature        签名结果缓冲区
*  @param[in]  max_buf_size     签名结果缓冲区大小
*  @param[out] signature_length 签名结果实际长度
*  @return     成功返回 SS_OK ，失败返回错误码
*  @remarks    不同开发者、不同许可的签名结果是不一样的。
*  @see        slm_license_verify 
*/
SS_UINT32 SSAPI slm_license_sign(
    IN  SLM_HANDLE_INDEX   slm_handle,
    IN  SS_BYTE           *sign_data,
    IN  SS_UINT32          sign_length,
    OUT SS_BYTE           *signature,
    IN  SS_UINT32          max_buf_size,
    OUT SS_UINT32         *signature_length
    );

/*!
*  @brief      对云许可签名后的数据进行验签（仅支持云锁）
*  @param[in]  sign_data        要签名的数据（最少 16字节，最大 64字节）
*  @param[in]  sign_length      要签名的数据长度
*  @param[in]  signature        签名结果数据
*  @param[in]  signature_length 签名结果长度
*  @param[out] sign_info        签名数据信息，json结构，不再使用时，需要调用 #slm_free 释放
*  @return     验签成功返回 SS_OK ，失败返回错误码
*  @remarks   -如果成功，需要调用 #slm_free 释放 sign_info
*             -验签过程可以不登录许可
*  @code 
   //json参数
   {
       "type":2,                                   // 2表示云锁
       "developer_id":0000000000000000,            // 开发商ID
       "license_id":0,                             // 许可ID
       "guid":xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,    // 用户guid（由类型决定）
       "sn":00000000000000000000000000000000,      // 锁号（由类型决定）
       "rand":0,                                   // 随机数
   }
   @endcode
*  @see  slm_license_sign slm_free
*/
SS_UINT32 SSAPI slm_license_verify(
    IN  SS_BYTE      *sign_data,
    IN  SS_UINT32       sign_length,
    IN  SS_BYTE      *signature,
    IN  SS_UINT32     signature_length,
    OUT char        **sign_info
    );

/*!
*   @brief      通过错误码获得错误信息
*   @param[in]  error_code  通过各 API 调用失败后返回的错误码值
*   @param[in]  language_id 要返回字符串的语言，见 #LANGUAGE_CHINESE_ASCII 等
*   @return     成功返回错误码文本描述信息（不需要调用 #slm_free 释放），失败返回空指针 NULL 
*   @remarks    特别注意：错误码文本描述信息，不需要调用 #slm_free 释放
*/
const SS_CHAR * SSAPI slm_error_format(
    IN SS_UINT32    error_code,
    IN SS_UINT32    language_id
    );

/*!
*   @brief      反初始化函数，与 #slm_init 对应
*   @see        slm_init
*   @remarks    #slm_cleanup 是非线程安全的，此函数不建议开发者调用，因为程序退出时系统会自动回收没有释放的内存，
*               若开发者调用，为了保证多线程调用 Runtime API 的安全性，此函数建议在程序退出时调用。
*               一旦调用了此函数，以上所有API（除 #slm_init ）均不可使用。
*/
SS_UINT32 SSAPI slm_cleanup(void);

/*!
*   @brief      扩展配置接口
*   @param[in]  config    配置参数（ #JSON ）
*               1. #slm_login 扩展参数，指定许可登录云锁、软锁服务地址，注意服务地址 URL 长度不得超过 #SLM_MAX_CLOUD_SERVER_LENGTH 宏定义长度。
*                           {"urls": {"cloud_runtime_url": "http://rt.senseyun.com","slock_url": "http://sl.senseyun.com","dl_url": "http://ll.senseyun.com"}}
*   @return     成功返回 SS_OK ，失败返回相应错误码
*   @remarks    不支持多线程调用，非线程安全，请保证配置在相关功能运行之前执行。
*/
SS_UINT32 SSAPI slm_extensions_config(IN const char *config);

#ifdef __cplusplus
};
#endif //__cplusplus

/**
*   @}
*/


#endif // #ifndef __SS_LM_RUMTIME_H__

