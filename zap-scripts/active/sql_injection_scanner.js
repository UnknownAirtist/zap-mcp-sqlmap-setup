/**
 * SQL Injection Scanner - Custom ZAP Active Script
 * This script enhances ZAP's built-in SQL injection detection capabilities
 */

// Scan parameters and cookies for SQL injection vulnerabilities
function scan(as, msg, param, value) {
    // All scan rules must support these callbacks
    if (msg.getHistoryRef().getHistoryType() === org.parosproxy.paros.model.HistoryReference.TYPE_TEMPORARY) {
        return;
    }
    
    // Debug message
    print('Scanning ' + msg.getRequestHeader().getURI().toString() + 
          ' for SQL injection vulnerabilities on parameter=' + param + 
          ' with value=' + value);
    
    // Get the parameter type
    var paramType;
    if (as.getParamType(param) == org.parosproxy.paros.core.scanner.NameValuePair.TYPE_QUERY_STRING) {
        paramType = "URL";
    } else if (as.getParamType(param) == org.parosproxy.paros.core.scanner.NameValuePair.TYPE_FORM_DATA) {
        paramType = "FORM";
    } else if (as.getParamType(param) == org.parosproxy.paros.core.scanner.NameValuePair.TYPE_COOKIE) {
        paramType = "COOKIE";
    } else {
        paramType = "UNKNOWN";
    }
    
    // SQL injection test payloads
    var payloads = [
        "'",
        "''",
        "\"",
        "\\",
        "'--",
        "'#",
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"\"=\"",
        "\" OR 1=1--",
        "' OR ''='",
        "' OR 'x'='x",
        "') OR ('x'='x",
        "1' OR '1'='1'#",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION ALL SELECT 1,2,3,4--",
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'x'='x'--",
        "' AND 'x'='y'--",
        "' AND (SELECT 1 FROM DUAL)=1--",
        "' AND (SELECT 1 FROM DUAL)=2--",
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SLEEP(5)--"
    ];
    
    // Error patterns to look for in responses
    var errorPatterns = [
        /SQL syntax.*MySQL/i,
        /Warning.*mysql_.*\(\)/i,
        /MySqlException \(0x/i,
        /valid MySQL result/i,
        /check the manual that corresponds to your (MySQL|MariaDB) server version/i,
        /Unknown column '[^']+' in 'field list'/i,
        /mysqli_fetch_array\(\)/i,
        /column.*not found/i,
        /Microsoft OLE DB Provider for ODBC Drivers error/i,
        /Microsoft SQL Native Client error/i,
        /SQLServer JDBC Driver/i,
        /ODBC SQL Server Driver/i,
        /SQLServerException/i,
        /com\.microsoft\.sqlserver\.jdbc/i,
        /Oracle.*Driver/i,
        /Warning.*oci_.*\(\)/i,
        /Oracle.*Error/i,
        /quoted string not properly terminated/i,
        /PostgreSQL.*ERROR/i,
        /Warning.*pg_.*\(\)/i,
        /valid PostgreSQL result/i,
        /Npgsql\./i,
        /PG::SyntaxError:/i,
        /org\.postgresql\.util\.PSQLException/i,
        /ERROR:\s\ssyntax error at or near /i,
        /Driver.*DB2/i,
        /db2_MSSQL_Exception/i,
        /DB2 SQL error:/i,
        /\[IBM\]\[CLI Driver\]\[DB2\/6000\]/i,
        /\[SQLITE_ERROR\]/i,
        /SQLite\/JDBCDriver/i,
        /SQLite\.Exception/i,
        /System\.Data\.SQLite\.SQLiteException/i
    ];
    
    // Time-based detection variables
    var normalResponseTime = 0;
    var delayedResponseTime = 0;
    
    // First get normal response time
    var startTime = new Date().getTime();
    var normalResponse = as.getNewMsg();
    as.sendAndReceive(normalResponse);
    var endTime = new Date().getTime();
    normalResponseTime = endTime - startTime;
    
    // Test each payload
    for (var i = 0; i < payloads.length; i++) {
        var testMsg = as.getNewMsg();
        var testValue = value + payloads[i];
        as.setParam(testMsg, param, testValue);
        
        // Send the payload
        startTime = new Date().getTime();
        as.sendAndReceive(testMsg);
        endTime = new Date().getTime();
        delayedResponseTime = endTime - startTime;
        
        // Check for error-based SQL injection
        var responseBody = testMsg.getResponseBody().toString();
        for (var j = 0; j < errorPatterns.length; j++) {
            if (errorPatterns[j].test(responseBody)) {
                as.newAlert()
                    .setRisk(org.parosproxy.paros.core.scanner.Alert.RISK_HIGH)
                    .setConfidence(org.parosproxy.paros.core.scanner.Alert.CONFIDENCE_MEDIUM)
                    .setName("SQL Injection Vulnerability")
                    .setDescription("SQL injection may be possible. The application appears to be vulnerable to SQL injection attacks.")
                    .setParam(param)
                    .setAttack(payloads[i])
                    .setEvidence(responseBody.match(errorPatterns[j])[0])
                    .setMessage(testMsg)
                    .raise();
                return;
            }
        }
        
        // Check for time-based SQL injection
        // If the delayed response is at least 5 seconds longer than the normal response for time-based payloads
        if ((i >= payloads.length - 2) && (delayedResponseTime > normalResponseTime + 4000)) {
            as.newAlert()
                .setRisk(org.parosproxy.paros.core.scanner.Alert.RISK_HIGH)
                .setConfidence(org.parosproxy.paros.core.scanner.Alert.CONFIDENCE_MEDIUM)
                .setName("Time-Based SQL Injection Vulnerability")
                .setDescription("Time-based SQL injection may be possible. The application appears to be vulnerable to SQL injection attacks.")
                .setParam(param)
                .setAttack(payloads[i])
                .setEvidence("Response time difference: Normal=" + normalResponseTime + "ms, Delayed=" + delayedResponseTime + "ms")
                .setMessage(testMsg)
                .raise();
            return;
        }
    }
}

// The scan function will be called for all request parameters
function scan(as, msg, param, value) {
    scan(as, msg, param, value);
}
