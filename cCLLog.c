/***********************************************************************************************************************
 * cCLog.c
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
/* Standard includes */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "cCLLog.h"

/***********************************************************************************************************************
 * External declarations
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Public variable definition
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private definitions
 **********************************************************************************************************************/
#define HEADER_LINE_PARSE_MAPPING_LENGTH ( sizeof( headerLineParseMapping ) / sizeof( headerLineParseMapping[ 0 ] ) )
#define MAX_LOG_LINE_LENGTH 200
#define TIME_STAMP_STRING_MAX_LENGTH ( sizeof( "YYYY/MM/DDThh:mm:ss.kkk" ) )
#define TIME_STAMP_STRING_STRIPPED_MAX_LENGTH ( sizeof( "YYYYMMDDhhmmsskkk" ) )

/***********************************************************************************************************************
 * Private type definitions
 **********************************************************************************************************************/
/* Function type to parse time stamps */
typedef void( *parseTimeStampFunc_t )( const char *pTimeStampString, cCLLog_timeStamp_t *pTs );

/* Function type to parse a single log file line */
typedef void( *parseFunc_t )( cCLLog_obj_t *pSelf, char *pLine );

/* Structure of the header parse mapping. A match string is paired with a parse function */
typedef struct
{
    const char *pMatchString;
    parseFunc_t parseFunc;
} headerLineParseMapping_t;

/* Time stucture type */
typedef struct tm tm_t;

/***********************************************************************************************************************
 * Private function declarations
 **********************************************************************************************************************/
static bool parseLogFileHeader( cCLLog_obj_t *pSelf );
static bool parseColumnHeader( cCLLog_obj_t *pSelf );
static bool parseColumnHeaderFields( cCLLog_obj_t *pSelf, char *pColLine );
static uint8_t stripTimeStamp( const cCLLog_logFileInfo_t *pInfo, char *pTimeStampString );
static bool fseekLine( cCLLog_obj_t *pSelf, uint32_t lineNo );

/* Parse time stamp functions */
static void parseTimeStamp( const cCLLog_logFileInfo_t *pInfo, const char *pTimeStampString, cCLLog_timeStamp_t *pTs );

/* Parse header lines functions */
static void parseLogFileHeaderLine_type( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_fwrev( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_hwrev( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_id( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_sessionNo( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_splitNo( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_time( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_valueSeparator( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_timeFormat( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_timeSeparator( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_timeSeparatorMs( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_dateSeparator( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_timeAndDateSeparator( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_bitRate( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_silentMode( cCLLog_obj_t *pSelf, char *pLine );
static void parseLogFileHeaderLine_cyclicMode( cCLLog_obj_t *pSelf, char *pLine );
/***********************************************************************************************************************
 * Private variable definitions
 **********************************************************************************************************************/

/* Array of header line match strings and associated parse functions */
static const headerLineParseMapping_t headerLineParseMapping[] =
{
    { .pMatchString = "Logger type: ", .parseFunc = parseLogFileHeaderLine_type},
    { .pMatchString = "HW rev: ", .parseFunc = parseLogFileHeaderLine_hwrev },
    { .pMatchString = "FW rev: ", .parseFunc = parseLogFileHeaderLine_fwrev },
    { .pMatchString = "Logger ID: ", .parseFunc = parseLogFileHeaderLine_id},
    { .pMatchString = "Session No.: ", .parseFunc = parseLogFileHeaderLine_sessionNo},
    { .pMatchString = "Split No.: ", .parseFunc = parseLogFileHeaderLine_splitNo},    
    { .pMatchString = "Time: ", .parseFunc = parseLogFileHeaderLine_time},
    { .pMatchString = "Value separator: ", .parseFunc = parseLogFileHeaderLine_valueSeparator},
    { .pMatchString = "Time format: ", .parseFunc = parseLogFileHeaderLine_timeFormat},
    { .pMatchString = "Time separator: ", .parseFunc = parseLogFileHeaderLine_timeSeparator},
    { .pMatchString = "Time separator ms: ", .parseFunc = parseLogFileHeaderLine_timeSeparatorMs},
    { .pMatchString = "Date separator: ", .parseFunc = parseLogFileHeaderLine_dateSeparator},
    { .pMatchString = "Time and date separator: ", .parseFunc = parseLogFileHeaderLine_timeAndDateSeparator},
    { .pMatchString = "Bit-rate: ", .parseFunc = parseLogFileHeaderLine_bitRate},
    { .pMatchString = "Silent mode: ", .parseFunc = parseLogFileHeaderLine_silentMode},
    { .pMatchString = "Cyclic mode: ", .parseFunc = parseLogFileHeaderLine_cyclicMode},
};

static int cCLLog_rewind_real(cCLLog_obj_t *pSelf)
{
    if (pSelf->pLogFile)
    {
        return fseek(pSelf->pLogFile, 0, SEEK_SET);
    }

    if (pSelf->rewind_func)
    {
        return pSelf->rewind_func(pSelf->file_data);
    }

    return -1;
}

static char *cCLLog_fgets_real(cCLLog_obj_t *pSelf, char *s, int size)
{
    if (pSelf->pLogFile)
    {
        return fgets(s, size, pSelf->pLogFile);
    }

    if (pSelf->gets_func)
    {
        return pSelf->gets_func(s, size, pSelf->file_data);
    }

    return NULL;
}

static bool cCLLog_ctor_common( cCLLog_obj_t *pSelf )
{
    bool resultFlag = false;

   /* Set parse function pointers */
    memset( pSelf->parseFieldFunc, 0, sizeof( pSelf->parseFieldFunc ) ); 

    {   
        /* Parser header */
        bool parseFileHeaderRes = parseLogFileHeader( pSelf );
        bool parseColumnHeaderRes = parseColumnHeader( pSelf );
            
        /* Set file pointer to first log row/line */
        bool seekRes = fseekLine( pSelf, pSelf->firstLogRow );  
            
        resultFlag = ( ( parseFileHeaderRes == true ) && 
                       ( parseColumnHeaderRes == true ) && 
                       ( seekRes == true ) ) ? true : false;
    }

    return resultFlag;    
}

bool cCLLog_ctor_wireshark( cCLLog_obj_t *pSelf, CLLog_gets_t func, CLLog_rewind_t rewind, void *data )
{
    bool resultFlag = false;

    if ( ( pSelf != NULL ) && ( func != NULL ) && (rewind != NULL ) )
    {
        pSelf->pLogFile = NULL;

        pSelf->gets_func = func;
        pSelf->rewind_func = rewind;
        pSelf->file_data = data;

        resultFlag = cCLLog_ctor_common(pSelf);
    }

    return resultFlag;    
}

/***********************************************************************************************************************
 * Public function definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * cCLLog_ctor
 *
 * cCLLog instance constructor. Must always be called prior to use of instance.
 *
 * @param[ in ]         pSelf           Pointer to the CLLog object
 * @param[ in ]         pLogFilePath    Log file path
 **********************************************************************************************************************/
bool cCLLog_ctor( cCLLog_obj_t *pSelf, const char *pLogFilePath )
{
    bool resultFlag = false;
                
    /* Input validation */
    if ( ( pSelf != NULL ) && ( pLogFilePath != NULL ) )
    {       
        /* Open log file */
        pSelf->pLogFile = fopen( pLogFilePath, "r" );
       
        /* Log file open ? */
        if ( pSelf->pLogFile != NULL ) 
        {   
            resultFlag = cCLLog_ctor_common(pSelf);
            if( resultFlag == false ) 
            {
                (void)cCLLog_dtor( pSelf );
            }
        }
    }
    return resultFlag;    
}

/***********************************************************************************************************************
 * cCLLog_dtor
 *
 * cCLLog instance destructor.
 *
 * @param[ in ]         pSelf           Pointer to the CLLog object
 **********************************************************************************************************************/
bool cCLLog_dtor( cCLLog_obj_t *pSelf )
{
    bool resultFlag = false;
    
    /* Input validation */
    if ( pSelf != NULL && pSelf->pLogFile != NULL )
    {
        fclose( pSelf->pLogFile );
        pSelf->pLogFile = NULL;
        resultFlag = true;
    }
    return resultFlag;
}

/***********************************************************************************************************************
 * cCLLog_fgets
 *
 * cCLLog read line form log file and move file pointer to next line 
 *
 * @param[ in ]         pSelf           Pointer to the CLLog object
 * @param[ out ]        pLogEntry       Log entry
 **********************************************************************************************************************/
static void parseFieldTS( cCLLog_logFileInfo_t *pInfo, char *pField, cCLLog_message_t *pLogEntry )
{
    parseTimeStamp( pInfo, pField, &pLogEntry->timestamp );
}
static void parseFieldLost( cCLLog_logFileInfo_t *pInfo, char *pField, cCLLog_message_t *pLogEntry )
{
    int lost = pLogEntry->lost;

    sscanf( pField, "%i", &lost );
    pLogEntry->lost = lost;
}
static void parseFieldMsgType( cCLLog_logFileInfo_t *pInfo, char *pField, cCLLog_message_t *pLogEntry )
{
    switch( pField[ 0 ] )
    {
        case '0':
            pLogEntry->msgType = msg_rx_standard_e;
            break;
        case '1':
            pLogEntry->msgType = msg_rx_extended_e;
            break;
        case '8':
            pLogEntry->msgType = msg_tx_standard_e;
            break;
        case '9':
            pLogEntry->msgType = msg_tx_extended_e;
            break;
    }
}
static void parseFieldID( cCLLog_logFileInfo_t *pInfo, char *pField, cCLLog_message_t *pLogEntry )
{
    sscanf( pField, "%x", &pLogEntry->id ); 
}
static void parseFieldLength( cCLLog_logFileInfo_t *pInfo, char *pField, cCLLog_message_t *pLogEntry )
{
    int length = pLogEntry->length;

    sscanf( pField, "%i", &length); 
    pLogEntry->length = length;
}
static void parseFieldData( cCLLog_logFileInfo_t *pInfo, char *pField, cCLLog_message_t *pLogEntry )
{
    char *pFieldStart = pField;
    
    /* Set data length in case length field is not set explicitly in the log file */
    pLogEntry->length = 0;    
    
    /* Loop all data bytes */
    for ( uint8_t dataByte = 0 ; dataByte < 8 ; dataByte++ ) 
    {
        unsigned int data = pLogEntry->data[ dataByte ];

        if( *pFieldStart == '\n' || *pFieldStart == '\r' ){ break; }
        
        sscanf( pFieldStart, "%2x", &data );
        pLogEntry->data[ dataByte ] = data;
                               
        /* Move on byte (two chars) forward */
        pFieldStart+=2;
        
        pLogEntry->length++;
    } 
}

static void parseLogLine( cCLLog_obj_t *pSelf, char *pLine, cCLLog_message_t *pLogEntry )
{
    char *pFieldStart = pLine;
    
    /* Loop all fields in log line */
    for ( uint8_t fieldNo = 0, finalField = 0 ; fieldNo < MAX_LOG_LINE_FIELDS && finalField == 0 ; fieldNo++ ) 
    {
        /* Find field end by separator */
        char *pFieldEnd = strchr( pFieldStart, pSelf->logFileInfo.separator );
        
        /* If final field, then EOL marks the end of the field */
        if( pFieldEnd == NULL ) 
        { 
            pFieldEnd = strchr( pFieldStart, '\n' );
            finalField = 1;
        }
                       
        /* Replace separator with string termination */
        *pFieldEnd = '\0';
        
        /* Is parse function assigned to field? */
        if( pSelf->parseFieldFunc[ fieldNo ] != NULL )
        {       
            /* Parse field */
            pSelf->parseFieldFunc[ fieldNo ]( &pSelf->logFileInfo, pFieldStart, pLogEntry );
        }
                       
        /* Set start of next field to end of privious + 1 */
        pFieldStart = pFieldEnd + 1;
    }    
}
 
int8_t cCLLog_fgets( cCLLog_obj_t *pSelf, cCLLog_message_t *pLogEntry )
{
    /* Read a line */
    char line[ MAX_LOG_LINE_LENGTH ];        
    char *pRes = cCLLog_fgets_real( pSelf, line, sizeof( line ));
    if( pRes != NULL )
    {
        /* Default the log entry structure */
        memset( pLogEntry, 0, sizeof( *pLogEntry ) );
        
        /* Parse the line */
        parseLogLine( pSelf, line, pLogEntry );
    }       
    return( ( pRes == NULL ) ? 0 : 1 );
}
 
/***********************************************************************************************************************
 Private function definitions
 **********************************************************************************************************************/
 /***********************************************************************************************************************
 * fseekLine
 *
 * Moves file pointer to a specific line number
 *
 * @param[ in ]         pSelf           Pointer to the CLLog object
 **********************************************************************************************************************/
static bool fseekLine( cCLLog_obj_t *pSelf, uint32_t lineNo )
{
    bool resultFlag = true;
    cCLLog_rewind_real( pSelf );
    char line[ MAX_LOG_LINE_LENGTH ];
    for( ; lineNo > 0; lineNo-- )
    {
        if( cCLLog_fgets_real( pSelf, line, sizeof( line )) == NULL ) { resultFlag = false; break; }
    }
    return resultFlag;
}
 
/***********************************************************************************************************************
 * parseLogFileHeader
 *
 * Parses the log file header
 *
 * @param[ in ]         pSelf           Pointer to the CLLog object
 **********************************************************************************************************************/
static bool parseLogFileHeader( cCLLog_obj_t *pSelf )
{
    char line[ MAX_LOG_LINE_LENGTH ];
    
    /* Deafault header */
    memset(  &pSelf->logFileInfo, 0, sizeof( pSelf->logFileInfo ) );
     
    /* Loop header line by line from start of file */
    cCLLog_rewind_real( pSelf );
    while ( cCLLog_fgets_real ( pSelf, line, sizeof( line ) ) != NULL )
    {       
        /* Break on end of header */
        if( line[ 0 ] != '#' ){ break; }
        
        for( uint8_t i = 0U ; i < HEADER_LINE_PARSE_MAPPING_LENGTH ; i++ )
        {
            const headerLineParseMapping_t *pHeaderMapping = &headerLineParseMapping[ i ];
            
            if ( ( strstr( line, pHeaderMapping-> pMatchString ) != NULL ) &&
                 ( pHeaderMapping->parseFunc != NULL ) )
            {
                pHeaderMapping->parseFunc( pSelf, line );
            }
        }
    }
    return true;
}

/***********************************************************************************************************************
 * parseColumnHeader
 *
 * Parses the column header line
 *
 * @param[ in ]         pSelf           Pointer to the CLLog object
 **********************************************************************************************************************/
static bool parseColumnHeader( cCLLog_obj_t *pSelf )
{    
    /* To test that the file header is found above column header */
    bool fileHeaderFound = false;
    bool columnHeaderFound = false;
  
    /* Line counter */
    uint32_t lineCounter = 0;
  
    char line[ MAX_LOG_LINE_LENGTH ];
  
    /* Find the first line after the header */
    cCLLog_rewind_real ( pSelf );
    while ( cCLLog_fgets_real ( pSelf, line, sizeof( line ) ) != NULL )
    {       
        /* Break on end of header */
        if( line[ 0 ] == '#' )
        { 
            fileHeaderFound = true;
        }
        else
        {
            if( fileHeaderFound == true )
            {
                pSelf->firstLogRow = lineCounter + 1;
                columnHeaderFound = parseColumnHeaderFields( pSelf, line );                
            }
            break;
        }
        lineCounter++;
    }
    return columnHeaderFound;
}

/***********************************************************************************************************************
 * parseColumnHeaderFields
 *
 * Parse the column fields and determine which fields are present and the position of the fields
 *
 * @param[ in ]         pSelf           Pointer to the CLLog object
 * @param[ in ]         pColLine        The column line
 **********************************************************************************************************************/
static bool parseColumnHeaderFields( cCLLog_obj_t *pSelf, char *pColLine )
{
    bool resultFlag = false;

    /* Initialise field start */
    char *pFieldStart = pColLine;
        
    /* Loop all fields in line */
    for ( uint8_t fieldNo = 0, finalField = 0 ; fieldNo < MAX_LOG_LINE_FIELDS && finalField == 0 ; fieldNo++ ) 
    {        
        /* Find field end */
        char *pFieldEnd = strchr( pFieldStart, pSelf->logFileInfo.separator );
        
        /* If final field, then EOL marks the end of the field */
        if( pFieldEnd == NULL ) 
        { 
            pFieldEnd = strchr( pFieldStart, '\n' );
            finalField = 1;
        }
        
        /* Replace separator with string termination */
        *pFieldEnd = '\0';
        
        /* Set field number */
        if( strcmp( pFieldStart, "Timestamp" ) == 0 )  { pSelf->parseFieldFunc[ fieldNo ] = parseFieldTS; resultFlag = true; }
        if( strcmp( pFieldStart, "Lost" ) == 0 )       { pSelf->parseFieldFunc[ fieldNo ] = parseFieldLost; resultFlag = true; }
        if( strcmp( pFieldStart, "Type" ) == 0 )       { pSelf->parseFieldFunc[ fieldNo ] = parseFieldMsgType; resultFlag = true; }
        if( strcmp( pFieldStart, "ID" ) == 0 )         { pSelf->parseFieldFunc[ fieldNo ] = parseFieldID; resultFlag = true; }
        if( strcmp( pFieldStart, "Length" ) == 0 )     { pSelf->parseFieldFunc[ fieldNo ] = parseFieldLength; resultFlag = true; }
        if( strcmp( pFieldStart, "Data" ) == 0 )       { pSelf->parseFieldFunc[ fieldNo ] = parseFieldData; resultFlag = true; }
                                
        /* Set start of next field to end of privious + 1 */
        pFieldStart = pFieldEnd + 1;
    }

    return resultFlag;
}

/***********************************************************************************************************************
 * parseTimeStamp
 *
 * Parse time stamp functions
 *
 * @param[ in ]         pTimeStampString    Time stamp string
 * @param[ out ]        pTs                 Return pointer
 **********************************************************************************************************************/
 /* TODO: Does not support separators set to numbers (will remove part of the time stamp also */
 /* TODO: Does not support time stamps without ms, as given in the header */
 /* TODO: Alot of copying slows down the parsing */
static void parseTimeStamp( const cCLLog_logFileInfo_t *pInfo, const char *pTimeStampString, cCLLog_timeStamp_t *pTs )
{
    /* First log time stamp as relative offset */
    static cCLLog_timeStampAbs_t firstTimeStampAbs = {0};
    
    /* Copy the string to not modify the original */
    char timeStampCopy[ TIME_STAMP_STRING_MAX_LENGTH ];
    strcpy( timeStampCopy, pTimeStampString );
    
    /* Copy the header time stamp string to not modify the original */
    char timeStampHeaderCopy[ TIME_STAMP_STRING_MAX_LENGTH ];
    strcpy( timeStampHeaderCopy, pInfo->logStartTimeString );

    /* Strip the delimiters from the time strings */
    uint8_t msgTimeStrippedLen = stripTimeStamp( pInfo, timeStampCopy );
    uint8_t headerTimeStrippedLen = stripTimeStamp( pInfo, timeStampHeaderCopy );
    
    /* Set time string (YYYYMMDDhhmmsskkk) to all zeros */
    char timeStampStringFull[ TIME_STAMP_STRING_STRIPPED_MAX_LENGTH ] = "19700101000000000";
    
    /* Copy the header time to the template */
    memcpy( timeStampStringFull, timeStampHeaderCopy, headerTimeStrippedLen );
      
    /* Copy the stripped timestamp into the full template */
    memcpy( &timeStampStringFull[ TIME_STAMP_STRING_STRIPPED_MAX_LENGTH - 1 - msgTimeStrippedLen ], timeStampCopy, msgTimeStrippedLen );
    timeStampStringFull[ TIME_STAMP_STRING_STRIPPED_MAX_LENGTH - 1 ] = '\0';
      
    tm_t tm;
    int ms;
    memset( &tm, 0, sizeof( tm ) );
          
    /* YYYYMMDDThhmmss */
    sscanf( timeStampStringFull, "%4u%2u%2u%2u%2u%2u%3u", 
            &tm.tm_year, 
            &tm.tm_mon, 
            &tm.tm_mday, 
            &tm.tm_hour, 
            &tm.tm_min, 
            &tm.tm_sec,
            &ms
            );
    tm.tm_mon -= 1;
    tm.tm_year -= 1900;
    
    /* To Epoch ( mktime converts to epoch from local (!!!) timezone )*/
    pTs->abs.epoch = mktime( &tm );  
    pTs->abs.ms = ms;
    
    /* Is first time stamp ? */
    if( firstTimeStampAbs.epoch == 0 && firstTimeStampAbs.ms == 0 )
    {
        firstTimeStampAbs.epoch = pTs->abs.epoch;
        firstTimeStampAbs.ms = pTs->abs.ms;
    }
    
    /* To relative time since start of file */
    pTs->rel.sec = (uint32_t)(pTs->abs.epoch - firstTimeStampAbs.epoch);
    pTs->rel.ms = pTs->abs.ms = ms;
}

/***********************************************************************************************************************
 * stripTimeStamp
 *
 * Strips a time stamp string for any delimiters
 *
 * @param[ in/out ]         pTimeStampString    Time stamp string
 **********************************************************************************************************************/
static uint8_t stripTimeStamp( const cCLLog_logFileInfo_t *pInfo, char *pTimeStampString )
{ 
    uint8_t strippedLength = 0U;
    
    /* Char by char, strip the delimiters from the time stamp string */
    uint8_t timeStampStringLen = (uint8_t) strlen( pTimeStampString );
    for( uint8_t i = 0U ; i < timeStampStringLen ; i++ )
    {
        /* Get char */
        char charTmp = pTimeStampString[ i ];
        
        /* If delimiter, skip */
        if( charTmp == pInfo->separator ){ continue; }
        if( charTmp == pInfo->timeSeparator ){ continue; }
        if( charTmp == pInfo->timeSeparatorMs ){ continue; }
        if( charTmp == pInfo->dateSeparator ){ continue; }
        if( charTmp == pInfo->dateAndTimeSeparator ){ continue; }
        
        /* Not a delimiter, keep char */
        pTimeStampString[ strippedLength++ ] = charTmp;
    }
    pTimeStampString[ strippedLength ] = '\0';
    
    return strippedLength;
}
/***********************************************************************************************************************
 * parseLogFileHeaderLine_X
 *
 * Parse log file header line functions
 *
 * @param[ in ]         pLine               Header line
 * @param[ out ]        pLogFileInfo        Return pointer
 **********************************************************************************************************************/
static char* getFieldValue( char *pLine )
{
    /* Set start pointer to fist byte in value */
    char *pFieldStart = strstr( pLine, ": ") + 2;
    
    /* Replace any newline chars with end of line */
    for( char *pChar = pFieldStart ; ; pChar++ )
    {   
        if( ( *pChar == '\n' ) || ( *pChar == '\r' ) || ( *pChar == '\0' ) )
        {
            *pChar = '\0';
            break;
        }
    }
    return pFieldStart;
} 
static char parseSeparator( char *pFieldValue )
{   
    char separator = '\0';
    /* Separator field is if set e.g. ";" - that is 3 chars. Else it is "" */
    if( strlen( pFieldValue ) == 3) 
    {
        sscanf( pFieldValue, "\"%c\"", &separator );
    }
    return separator;
}
static void parseHeaderTime( const char *pTimeStampString, cCLLog_timeStamp_t *pTs )
{   
    tm_t tm;
    memset( &tm, 0, sizeof( tm ) );  
          
    /* YYYYMMDDThhmmss */
    sscanf( pTimeStampString, 
            "%4u%2u%2uT%2u%2u%2u", 
            &tm.tm_year, 
            &tm.tm_mon, 
            &tm.tm_mday, 
            &tm.tm_hour, 
            &tm.tm_min, 
            &tm.tm_sec );
    tm.tm_mon -= 1;
    tm.tm_year -= 1900;
      
    /* To Epoch ( mktime converts to epoch from local (!!!) timezone )*/
    pTs->abs.epoch = mktime( &tm );
    pTs->abs.ms = 0;
}
static void parseLogFileHeaderLine_type( cCLLog_obj_t *pSelf, char *pLine )
{
    if( strcmp( getFieldValue( pLine ), "CANLogger1000" ) == 0 ){ pSelf->logFileInfo.loggerType = type_CL1000_e; }
    if( strcmp( getFieldValue( pLine ), "CANLogger2000" ) == 0 ){ pSelf->logFileInfo.loggerType = type_CL2000_e; }
    if( strcmp( getFieldValue( pLine ), "CANLogger3000" ) == 0 ){ pSelf->logFileInfo.loggerType = type_CL3000_e; }
}
static void parseLogFileHeaderLine_hwrev( cCLLog_obj_t *pSelf, char *pLine )
{
    sscanf( getFieldValue( pLine ), "%s", &pSelf->logFileInfo.hwrev );
}
static void parseLogFileHeaderLine_fwrev( cCLLog_obj_t *pSelf, char *pLine )
{
    sscanf( getFieldValue( pLine ), "%s", &pSelf->logFileInfo.fwrev );
}
static void parseLogFileHeaderLine_id( cCLLog_obj_t *pSelf, char *pLine )
{
    sscanf( getFieldValue( pLine ), "%s", &pSelf->logFileInfo.id[ 0 ] );
}
static void parseLogFileHeaderLine_sessionNo( cCLLog_obj_t *pSelf, char *pLine )
{
    sscanf( getFieldValue( pLine ), "%i", &pSelf->logFileInfo.sessionNo );
}
static void parseLogFileHeaderLine_splitNo( cCLLog_obj_t *pSelf, char *pLine )
{
    sscanf( getFieldValue( pLine ), "%i", &pSelf->logFileInfo.splitNo );
}
static void parseLogFileHeaderLine_time( cCLLog_obj_t *pSelf, char *pLine )
{
    const char *pFieldStart = getFieldValue( pLine );
    parseHeaderTime( pFieldStart, &pSelf->logFileInfo.logStartTime );
    memcpy( pSelf->logFileInfo.logStartTimeString, pFieldStart, strlen( pFieldStart ) );
}
static void parseLogFileHeaderLine_valueSeparator( cCLLog_obj_t *pSelf, char *pLine )
{
    pSelf->logFileInfo.separator = parseSeparator( getFieldValue( pLine ) );
}
static void parseLogFileHeaderLine_timeFormat( cCLLog_obj_t *pSelf, char *pLine )
{
    int formatTmp = 0;
    sscanf( getFieldValue( pLine ), "%i", &formatTmp );
    pSelf->logFileInfo.timeFormat = (uint8_t)formatTmp;
}
static void parseLogFileHeaderLine_timeSeparator( cCLLog_obj_t *pSelf, char *pLine )
{
    pSelf->logFileInfo.timeSeparator = parseSeparator( getFieldValue( pLine ) );
}
static void parseLogFileHeaderLine_timeSeparatorMs( cCLLog_obj_t *pSelf, char *pLine )
{
    pSelf->logFileInfo.timeSeparatorMs = parseSeparator( getFieldValue( pLine ) );
}
static void parseLogFileHeaderLine_dateSeparator( cCLLog_obj_t *pSelf, char *pLine )
{
    pSelf->logFileInfo.dateSeparator = parseSeparator( getFieldValue( pLine ) );
}
static void parseLogFileHeaderLine_timeAndDateSeparator( cCLLog_obj_t *pSelf, char *pLine )
{
    pSelf->logFileInfo.dateAndTimeSeparator = parseSeparator( getFieldValue( pLine ) );
}
static void parseLogFileHeaderLine_bitRate( cCLLog_obj_t *pSelf, char *pLine )
{
    sscanf( getFieldValue( pLine ), "%i", &pSelf->logFileInfo.bitRate );
}
static void parseLogFileHeaderLine_silentMode( cCLLog_obj_t *pSelf, char *pLine )
{
    if( strcmp( getFieldValue( pLine ), "true" ) == 0 ){ pSelf->logFileInfo.silentMode = silent_enabled_e; }
    if( strcmp( getFieldValue( pLine ), "false" ) == 0 ){ pSelf->logFileInfo.silentMode = silent_disabled_e; }
}
static void parseLogFileHeaderLine_cyclicMode( cCLLog_obj_t *pSelf, char *pLine )
{
    if( strcmp( getFieldValue( pLine ), "true" ) == 0 ){ pSelf->logFileInfo.cyclicMode = cyclic_enabled_e; }
    if( strcmp( getFieldValue( pLine ), "false" ) == 0 ){ pSelf->logFileInfo.cyclicMode = cyclic_disabled_e; }
}


/*

         c:\development\wireshark\plugins\wimaxmacphy\cCLLog.c(248): warning C4
       477: 'sscanf' : format string '%i' requires an argument of type 'int *',
        but variadic argument 1 has type 'uint8_t *'
         c:\development\wireshark\plugins\wimaxmacphy\cCLLog.c(274): warning C4
       477: 'sscanf' : format string '%i' requires an argument of type 'int *',
        but variadic argument 1 has type 'uint8_t *'
         c:\development\wireshark\plugins\wimaxmacphy\cCLLog.c(288): warning C4
       477: 'sscanf' : format string '%2x' requires an argument of type 'unsign
       ed int *', but variadic argument 1 has type 'uint8_t *


*/
