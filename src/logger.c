#include "logger.h"

gchar *getCurrentDateTimeAsISOString() {
    GTimeVal theTime;
    g_get_current_time(&theTime);
    return g_time_val_to_iso8601(&theTime);
}

void logConnected(gchar *clientIP, gchar *clientPort) {
    FILE *fp;
    fp = fopen("log.txt", "a"); /* Open file and append to it */
    if(fp != NULL) {
        gchar *theTime = getCurrentDateTimeAsISOString();
        gchar *logMsg = g_strconcat(theTime, " : ", clientIP, ":", clientPort, " connected\n", NULL);
        fwrite(logMsg, sizeof(char), strlen(logMsg), fp);
        g_free(logMsg);
        g_free(theTime);
        fclose(fp);
    } else {
        g_printf("Error with logging! File couldn't be opened.");
    }
}

void logDisconnected(gchar *clientIP, gchar *clientPort) {
    FILE *fp;
    fp = fopen("log.txt", "a"); /* Open file and append to it */
    if(fp != NULL) {
        gchar *theTime = getCurrentDateTimeAsISOString();
        gchar *logMsg = g_strconcat(theTime, " : ", clientIP, ":", clientPort, " disconnected\n", NULL);
        fwrite(logMsg, sizeof(char), strlen(logMsg), fp);
        g_free(logMsg);
        g_free(theTime);
        fclose(fp);
    } else {
        g_printf("Error with logging! File couldn't be opened.");
    }
}
