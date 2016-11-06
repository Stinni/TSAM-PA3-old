#include "logger.h"

/* TODO: see if this is needed, it might not be... */
gchar *getCurrentDateTimeAsString() {
    GDateTime *currTime  = g_date_time_new_now_local();
    gchar *dateAsString = g_date_time_format(currTime, "%a, %d %b %Y %H:%M:%S %Z");
    g_date_time_unref(currTime);
    return dateAsString;
}

gchar *getCurrentDateTimeAsISOString() {
    GTimeVal theTime;
    g_get_current_time(&theTime);
    return g_time_val_to_iso8601(&theTime);
}

void logRecvMessage(gchar *clientIP, gchar *clientPort, gchar *reqMethod, gchar *host, gchar *reqURL, gchar *code) {
    FILE *fp;
    fp = fopen("log.txt", "a"); /* Open file and append to it */
    if(fp != NULL) {
        gchar *theTime = getCurrentDateTimeAsISOString();
        gchar *logMsg = g_strconcat(theTime, " : ", clientIP, ":", clientPort, " ", reqMethod, " ", host, reqURL, " : ", code, "\n", NULL);
        fwrite(logMsg, sizeof(char), strlen(logMsg), fp);
        g_free(logMsg);
        g_free(theTime);
        fclose(fp);
    } else {
        g_printf("Error with logging! File couldn't be opened.");
    }
}
