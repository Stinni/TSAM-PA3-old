#include <string.h>
#include <time.h>
#include <glib.h>
#include <glib/gprintf.h>

gchar *getCurrentDateTimeAsISOString();
void logConnected(gchar *clientIP, gchar *clientPort);
void logDisconnected(gchar *clientIP, gchar *clientPort);
