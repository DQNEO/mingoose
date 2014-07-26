#include "mingoose.h"

const struct mime_type builtin_mime_types[] = {
    {".html", 5, "text/html"},
    {".htm", 4, "text/html"},
    {".shtm", 5, "text/html"},
    {".shtml", 6, "text/html"},
    {".css", 4, "text/css"},
    {".js",  3, "application/x-javascript"},
    {".ico", 4, "image/x-icon"},
    {".gif", 4, "image/gif"},
    {".jpg", 4, "image/jpeg"},
    {".jpeg", 5, "image/jpeg"},
    {".png", 4, "image/png"},
    {".svg", 4, "image/svg+xml"},
    {".txt", 4, "text/plain"},
    {".torrent", 8, "application/x-bittorrent"},
    {".wav", 4, "audio/x-wav"},
    {".mp3", 4, "audio/x-mp3"},
    {".mid", 4, "audio/mid"},
    {".m3u", 4, "audio/x-mpegurl"},
    {".ogg", 4, "application/ogg"},
    {".ram", 4, "audio/x-pn-realaudio"},
    {".xml", 4, "text/xml"},
    {".json",  5, "text/json"},
    {".xslt", 5, "application/xml"},
    {".xsl", 4, "application/xml"},
    {".ra",  3, "audio/x-pn-realaudio"},
    {".doc", 4, "application/msword"},
    {".exe", 4, "application/octet-stream"},
    {".zip", 4, "application/x-zip-compressed"},
    {".xls", 4, "application/excel"},
    {".tgz", 4, "application/x-tar-gz"},
    {".tar", 4, "application/x-tar"},
    {".gz",  3, "application/x-gunzip"},
    {".arj", 4, "application/x-arj-compressed"},
    {".rar", 4, "application/x-arj-compressed"},
    {".rtf", 4, "application/rtf"},
    {".pdf", 4, "application/pdf"},
    {".swf", 4, "application/x-shockwave-flash"},
    {".mpg", 4, "video/mpeg"},
    {".webm", 5, "video/webm"},
    {".mpeg", 5, "video/mpeg"},
    {".mov", 4, "video/quicktime"},
    {".mp4", 4, "video/mp4"},
    {".m4v", 4, "video/x-m4v"},
    {".asf", 4, "video/x-ms-asf"},
    {".avi", 4, "video/x-msvideo"},
    {".bmp", 4, "image/bmp"},
    {".ttf", 4, "application/x-font-ttf"},
    {NULL,  0, NULL}
};

const char *mg_get_builtin_mime_type(const char *path) {
    const char *ext;
    size_t i, path_len;

    path_len = strlen(path);

    for (i = 0; builtin_mime_types[i].extension != NULL; i++) {
        ext = path + (path_len - builtin_mime_types[i].ext_len);
        if (path_len > builtin_mime_types[i].ext_len &&
            mg_strcasecmp(ext, builtin_mime_types[i].extension) == 0) {
            return builtin_mime_types[i].mime_type;
        }
    }

    return "text/plain";
}
