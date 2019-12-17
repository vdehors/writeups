#define uint32_t uint
#define size_t ulonglong
#define uint16_t uint16
#define uint8_t unsigned char

typedef uint32_t TEEC_Result;

typedef struct {
  void *buffer;
  size_t size;
  uint32_t flags;
  int id;
  size_t alloced_size;
  void *shadow_buffer;
  int registered_fd;
  bool buffer_allocated;
} TEEC_SharedMemory;

typedef struct {
  /* Implementation defined */
  int fd;
  bool reg_mem;
} TEEC_Context;

typedef struct {
  uint32_t a;
  uint32_t b;
  uint32_t pad;
} TEEC_Value;

typedef struct {
  uint32_t timeLow;
  uint16_t timeMid;
  uint16_t timeHiAndVersion;
  uint8_t clockSeqAndNode[8];
} TEEC_UUID;

typedef struct {
  void *buffer;
  size_t size;
} TEEC_TempMemoryReference;

typedef struct {
  TEEC_SharedMemory *parent;
  size_t size;
  size_t offset;
} TEEC_RegisteredMemoryReference;

typedef union {
  TEEC_TempMemoryReference tmpref;
  TEEC_RegisteredMemoryReference memref;
  TEEC_Value value;
} TEEC_Parameter;

typedef struct {
  /* Implementation defined */
  TEEC_Context *ctx;
  uint32_t session_id;
} TEEC_Session;

#define TEEC_CONFIG_PAYLOAD_REF_COUNT 4
typedef struct {
  uint32_t started;
  uint32_t paramTypes;
  TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
  /* Implementation-Defined */
  TEEC_Session *session;
} TEEC_Operation;
