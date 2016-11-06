#include <string.h>
#include <time.h>
#include <glib.h>
#include <glib/gprintf.h>

gchar *getCurrentDateTimeAsString();
gchar *getCurrentDateTimeAsISOString();
void logRecvMessage(gchar *clientIP, gchar *clientPort, gchar *reqMethod, gchar *host, gchar *reqURL, gchar *code);
