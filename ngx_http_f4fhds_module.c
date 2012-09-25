/*
 * 
 * copyright (c) 2010, 2012 ZAO Inventos (http://www.inventos.ru)
 * copyright (c) 2010, 2012 jk@inventos.ru
 *
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published
    by the Free Software Foundation, either version 2.1 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <memory.h>

#define VERSION "0.4"
 
static char *ngx_http_f4fhds(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_f4fhds_commands[] = {
    { ngx_string("f4fhds"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_f4fhds,
      0,
      0,
      NULL },
    ngx_null_command
};
 

static ngx_http_module_t ngx_http_f4fhds_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */
 
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
 
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
 
    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};
 
 
ngx_module_t ngx_http_f4fhds_module = {
    NGX_MODULE_V1,
    &ngx_http_f4fhds_module_ctx,  /* module context */
    ngx_http_f4fhds_commands,     /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static uint16_t get16(const u_char *buf) {
    return buf[0] * 0x100 + buf[1];
}

static uint32_t get32(const u_char *buf) {
    return buf[0] * 0x1000000 + buf[1] * 0x10000 + buf[2] * 0x100 + buf[3];
}

static uint64_t get64(const u_char *buf) {
    return get32(buf) * 0x100000000ULL + get32(buf + 4);
}


static ngx_int_t make_mapping(const char *filename, ngx_str_t *pmap, ngx_http_request_t *r) {
    int fd;
    struct stat st;
    void *addr;

    fd = open(filename, O_RDONLY);
    if ( fd == -1 ) {
        int e = errno;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno, "opening %s", filename);
        return ( e == ENOENT || e == ENOTDIR ) ? NGX_HTTP_NOT_FOUND : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if ( fstat(fd, &st) == -1 ) {
        close(fd);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno, "stat %s", filename);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    addr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if ( addr == (void*)(-1) ) {
        close(fd);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno, "mmap %s", filename);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    close(fd);
    pmap->data = (u_char*)addr;
    pmap->len = st.st_size;
    return NGX_OK;
}

static void free_mapping(ngx_str_t *pmap) {
    if ( pmap->data && pmap->len )
        munmap(pmap->data, pmap->len);
}

static unsigned long long getboxlen(const u_char *ptr) {
    unsigned value = get32(ptr);
    if ( value == 1 ) {
        return get64(ptr + 8);
    }
    return value;
}



static ngx_int_t ngx_http_f4fhds_handler(ngx_http_request_t *r)
{
    ngx_int_t    rc;
    ngx_chain_t  out;
    u_char *resp_body;
    ngx_buf_t   *resp;
    char *lastslash;
    char *segsuffix;
    size_t root;
    ngx_str_t path;
    ngx_str_t index_map = ngx_null_string;
    ngx_str_t mediafile_map = ngx_null_string;
    unsigned fragnum;
    uint32_t totalsize;
    ngx_table_elt_t *self;

    unsigned afraentries;
    unsigned g_afraentries, g_entry_size = 0;
    unsigned globaltable_offset;
    unsigned long long afraoffset = 0, offsetfromafra = 0;
    unsigned entryindex = 0;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }
 
    if ( (rc = ngx_http_discard_request_body(r)) != NGX_OK ) {
        return rc;
    }

    if ( (self = ngx_list_push(&r->headers_out.headers)) == NULL ) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Insufficient memory for ngx_list_push");
        return NGX_ERROR;
    }
    self->hash = 1;
    ngx_str_set(&self->key, "X-Inventos-F4FHDS-Version");
    ngx_str_set(&self->value, VERSION);
 
    ngx_http_map_uri_to_path(r, &path, &root, 0);

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "path=%s", path.data);

    lastslash = strrchr((char*)path.data, '/');
    ++lastslash;
    segsuffix = (char *)memmem(lastslash, path.len - (lastslash - (char *)path.data), "Seg1-Frag", 9);
    if ( segsuffix == NULL ) {
        return NGX_HTTP_NOT_FOUND;
    }
    segsuffix += 4; /* "Seg1" */

    fragnum = atoi(segsuffix + /* "-Frag" */ 5);
    if ( fragnum < 1 ) {
        return NGX_HTTP_NOT_FOUND;
    }

    memcpy(segsuffix, ".f4x", 4);
    path.len = segsuffix - (char*)path.data + 4;
    segsuffix[4] = 0;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "f4x_path=%s", path.data);
    if ( (rc = make_mapping((const char *)path.data, &index_map, r)) != NGX_OK ) {
        return rc;
    }

    if ( index_map.len < 8 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Wrong f4x afra size: %d in %s", index_map.len, path.data);
        goto GENERAL_ERROR;
    }
    if ( memcmp(index_map.data + 4, "afra", 4) != 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Wrong f4x format: %s", path.data);
        goto GENERAL_ERROR;
    }
    if ( getboxlen(index_map.data) != index_map.len ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Wrong f4x prefix size: %d in %s", get32(index_map.data), path.data);
        goto GENERAL_ERROR;
    }

    if ( (index_map.data[12] & 0x20) == 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Global entries are not present in %s", path.data);
        goto GENERAL_ERROR;
    }

    afraentries = get32(index_map.data + 17);
    globaltable_offset = 17 + 4 + afraentries * (8 /* time */ + ((index_map.data[12] & 0x40) ? 8 : 4)) + 4;
    if ( index_map.len < globaltable_offset ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Index file too short: %s", path.data);
        goto GENERAL_ERROR;
    }
    g_afraentries = get32(index_map.data + globaltable_offset - 4);

    switch ( index_map.data[12] & 0xc0 ) {
    case 0xc0: 
        g_entry_size = 32; 
        break;
    case 0x80: 
        g_entry_size = 24; 
        break;
    case 0x40: 
        g_entry_size = 28; 
        break;
    case 0:    
        g_entry_size = 20; 
        break;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "globaltable_offset=%d, afraentries=%d, g_afraentries=%d, entrysize=%d", 
                      globaltable_offset, afraentries, g_afraentries, g_entry_size
                     );

    if ( index_map.len < globaltable_offset + g_afraentries * g_entry_size ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Index file too short: %s, len=%d, need=%d, globaltable_offset=%d, afraentries=%d, g_afraentries=%d, entrysize=%d", 
                      path.data, index_map.len, globaltable_offset + g_afraentries * g_entry_size,
                      globaltable_offset, afraentries, g_afraentries, g_entry_size
                     );
        goto GENERAL_ERROR;
    }

#define FIND_SEGMENT(SEGSIZE, FRAGSIZE, AOSIZE, OFASIZE) \
        for ( entryindex = 0; entryindex < g_afraentries; ++entryindex ) { \
            u_char *pentry = index_map.data + globaltable_offset + entryindex * g_entry_size; \
            unsigned segment = get##SEGSIZE (pentry + 8); \
            unsigned fragment = get##FRAGSIZE (pentry + 8 + SEGSIZE/8); \
            if ( segment == 1 && fragment == fragnum ) { \
                afraoffset = get##AOSIZE (pentry + 8 + SEGSIZE/8 + FRAGSIZE/8); \
                offsetfromafra = get##OFASIZE (pentry + 8 + SEGSIZE/8 + FRAGSIZE/8 + AOSIZE/8); \
                break; \
            } \
        }


    switch ( index_map.data[12] & 0xc0 ) {
    case 0xc0: 
        FIND_SEGMENT(32, 32, 64, 64);
        break;
    case 0x80: 
        FIND_SEGMENT(32, 32, 32, 32);
        break;
    case 0x40: 
        FIND_SEGMENT(16, 16, 64, 64);
        break;
    case 0:    
        FIND_SEGMENT(16, 16, 32, 32);
        break;
    }
    if ( entryindex == g_afraentries ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Fragment #%d not found in %s, g_afraentries=%d", fragnum, path.data, g_afraentries);
        goto NOT_FOUND;
    }
    if ( offsetfromafra != 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OffsetFromAfra=%llu not supported, %s", offsetfromafra, path.data);
        goto GENERAL_ERROR;
    }


    memcpy(segsuffix, ".f4f", 4);
    if ( (rc = make_mapping((const char *)path.data, &mediafile_map, r)) != NGX_OK ) {
        return rc;
    }

    if ( mediafile_map.len < afraoffset + 8 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Mediafile is too short: %s", path.data);
        goto GENERAL_ERROR;
    }

    {
    const u_char *afra = mediafile_map.data + afraoffset;
    unsigned long long afralen = getboxlen(afra);
    const u_char *abst = afra + afralen;
    unsigned long long abstlen = getboxlen(abst);
    const u_char *moof = abst + abstlen;
    unsigned long long mooflen = getboxlen(moof);
    const u_char *mdat = moof + mooflen;
    unsigned long long mdatlen = getboxlen(mdat);
    totalsize = afralen + abstlen + mooflen + mdatlen;
    if ( (resp_body = ngx_pcalloc(r->pool, totalsize)) == NULL ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Insufficient memory");
        goto GENERAL_ERROR;
    }
    memcpy(resp_body, afra, totalsize);
    }

    if ( (resp = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Insufficient memory");
        goto GENERAL_ERROR;
    }
 
    out.buf = resp;
    out.next = NULL;

    resp->pos = resp_body;
    resp->last = resp_body + totalsize;
    resp->memory = 1; 
    resp->last_buf = 1;
 
    free_mapping(&index_map);
    free_mapping(&mediafile_map);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = totalsize;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only || r->method == NGX_HTTP_HEAD) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);

GENERAL_ERROR:
    free_mapping(&index_map);
    free_mapping(&mediafile_map);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;

NOT_FOUND:
    free_mapping(&index_map);
    free_mapping(&mediafile_map);
    return NGX_HTTP_NOT_FOUND;

}
 
 
static char *ngx_http_f4fhds(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
 
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_f4fhds_handler;
 
    return NGX_CONF_OK;
}
