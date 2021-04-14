/***********************************************************************************************************************
 * @file	cCLLog.h
 **********************************************************************************************************************/
#ifndef CCLLOG_H_
#define CCLLOG_H_

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
/***********************************************************************************************************************
 * Public definitions
 **********************************************************************************************************************/
#define MAX_LOG_LINE_FIELDS 7 /*( seqNo, timestamp, lost, SE, ID, length, data) */
/***********************************************************************************************************************
 * Public type declarations
 **********************************************************************************************************************/
/* Absolute time stamp structure type (epoch time + ms resolution) */
typedef struct { time_t epoch; uint16_t ms; } cCLLog_timeStampAbs_t;

/* Relative time stamp structure type (sec since start + ms resolution) */
typedef struct { uint32_t sec; uint16_t ms; } cCLLog_timeStampRel_t;
 
 /* Time stamp with abs and rel time */
typedef struct { cCLLog_timeStampAbs_t abs; cCLLog_timeStampRel_t rel; } cCLLog_timeStamp_t;
 
 /* Messasge type */
typedef enum 
{ 
    msg_rx_standard_e = 0, 
    msg_rx_extended_e = 1,
    msg_tx_standard_e = 7, 
    msg_tx_extended_e = 8,
} cCLLog_messageType_t;

/* Typedef CAN-bus message type */
typedef struct
{
    cCLLog_timeStamp_t timestamp;
    uint8_t lost;
    cCLLog_messageType_t msgType;
    uint32_t id;
    uint8_t length;
    uint8_t data[ 8 ];
} cCLLog_message_t;

/* Silent-mode*/
typedef enum { silent_disabled_e = 0, silent_enabled_e } cCLLog_silentMode_t;

/* Cyclic-mode*/
typedef enum { cyclic_disabled_e = 0, cyclic_enabled_e } cCLLog_cyclicMode_t;

/* Logger type */
typedef enum { type_CL1000_e = 0, type_CL2000_e, type_CL3000_e } cCLLog_loggerType_t;

 /* Log file information */
typedef struct
{
    cCLLog_loggerType_t loggerType;
    char hwrev[5];
    char fwrev[5];
    char id[20];
    uint32_t sessionNo;
    uint32_t splitNo;
    cCLLog_timeStamp_t logStartTime;
    char logStartTimeString[ 20 ];
    char separator;
    uint8_t timeFormat;
    char timeSeparator;
    char timeSeparatorMs;
    char dateSeparator;
    char dateAndTimeSeparator;
    uint32_t bitRate;
    cCLLog_silentMode_t silentMode;
    cCLLog_cyclicMode_t cyclicMode;
} cCLLog_logFileInfo_t;

typedef char * (*CLLog_gets_t)(char *s, int size, void *stream);
typedef int (*CLLog_rewind_t)(void *stream);


/* Type used to parse a field in a log line */
typedef void( *parseFieldFunc_t )( cCLLog_logFileInfo_t *pInfo, char *pField, cCLLog_message_t *pLogEntry );
  
/* Object instance type (self) */
typedef struct
{
    CLLog_gets_t gets_func;
    CLLog_rewind_t rewind_func;
    void *file_data;

    FILE *pLogFile;
    uint32_t firstLogRow;
    cCLLog_logFileInfo_t logFileInfo;
    parseFieldFunc_t parseFieldFunc[ MAX_LOG_LINE_FIELDS ];
} cCLLog_obj_t;

/***********************************************************************************************************************
 * Public function declarations
 **********************************************************************************************************************/
bool cCLLog_ctor( cCLLog_obj_t *pSelf, const char *pLogFilePath );
bool cCLLog_ctor_wireshark( cCLLog_obj_t *pSelf, CLLog_gets_t func, CLLog_rewind_t rewind, void *data );
bool cCLLog_dtor( cCLLog_obj_t *pSelf );
int8_t cCLLog_fgets( cCLLog_obj_t *pSelf, cCLLog_message_t *pLogEntry );

#endif // CCLLOG_H_
