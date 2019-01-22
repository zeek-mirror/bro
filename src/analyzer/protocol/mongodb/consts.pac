# Operate code */
enum OPCODE {
    OP_REPLY        =    1, #Reply to a client request. responseTo is set.
# OP_MESSAGE        = 1000,
    OP_UPDATE       = 2001, #Update document.
    OP_INSERT       = 2002, #Insert new document.
    OP_RESERVED     = 2003, #RESERVED Formerly used for OP_GET_BY_OID.
    OP_QUERY        = 2004, #Query a collection.
    OP_GET_MORE     = 2005, #Get more data from a query. See Cursors.
    OP_DELETE       = 2006, #Delete documents.
    OP_KILL_CURSORS = 2007, #Notify database that the client has finished with the cursor.
    OP_COMMAND      = 2010, #Cluster internal protocol representing a command request.
    OP_COMMANDREPLY = 2011, #Cluster internal protocol representing a reply to an OP_COMMAND.
    OP_COMPRESSED   = 2012,
    OP_MSG          = 2013  #Send a message using the format introduced in MongoDB 3.6.
};

# BSON Element types */
# See http://bsonspec.org/#/specification for detail */
enum BSON_ELEMENT_TYPE {
    BSON_ELEMENT_TYPE_DOUBLE        =   1,
    BSON_ELEMENT_TYPE_STRING        =   2,
    BSON_ELEMENT_TYPE_DOC           =   3,
    BSON_ELEMENT_TYPE_ARRAY         =   4,
    BSON_ELEMENT_TYPE_BINARY        =   5,
    BSON_ELEMENT_TYPE_UNDEF         =   6,# Deprecated */
    BSON_ELEMENT_TYPE_OBJ_ID        =   7,
    BSON_ELEMENT_TYPE_BOOL          =   8,
    BSON_ELEMENT_TYPE_DATETIME      =   9,
    BSON_ELEMENT_TYPE_NULL          =  10,
    BSON_ELEMENT_TYPE_REGEX         =  11,
    BSON_ELEMENT_TYPE_DB_PTR        =  12,# Deprecated */
    BSON_ELEMENT_TYPE_JS_CODE       =  13,
    BSON_ELEMENT_TYPE_SYMBOL        =  14,
    BSON_ELEMENT_TYPE_JS_CODE_SCOPE =  15,
    BSON_ELEMENT_TYPE_INT32         =  16,# 0x10 */
    BSON_ELEMENT_TYPE_TIMESTAMP     =  17,# 0x11 */
    BSON_ELEMENT_TYPE_INT64         =  18,# 0x12 */
    BSON_ELEMENT_TYPE_MIN_KEY       = 255,# 0xFF */
    BSON_ELEMENT_TYPE_MAX_KEY       = 127 # 0x7F */
};

enum COMPRESSOR_METHOD {
    MONGO_COMPRESSOR_NOOP    = 0,
    MONGO_COMPRESSOR_SNAPPY  = 1,
    MONGO_COMPRESSOR_ZLIB    = 2
};

enum BSON_ELEMENT_BINARY_TYPE {
    BSON_ELEMENT_BINARY_TYPE_GENERIC    =   0,
    BSON_ELEMENT_BINARY_TYPE_FUNCTION   =   1,
    BSON_ELEMENT_BINARY_TYPE_BINARY     =   2,# OLD */
    BSON_ELEMENT_BINARY_TYPE_UUID       =   3,
    BSON_ELEMENT_BINARY_TYPE_MD5        =   4,
    BSON_ELEMENT_BINARY_TYPE_USER       = 128 # 0x80 */
};
