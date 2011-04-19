
/*
 * Copyright (C) Kirill A. Korinskiy
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flathash_t           *hash;
    ngx_uint_t                size;
    ngx_uint_t                rate;
    ngx_shmtx_t               mutex;
    ngx_http_complex_value_t  key;
} ngx_http_limit_var_ctx_t;


static char *ngx_http_limit_var(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_limit_var_commands[] = {

    { ngx_string("limit_var"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_limit_var,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_var_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configration */
    NULL                                   /* merge location configration */
};


ngx_module_t  ngx_http_limit_var_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_var_module_ctx,        /* module context */
    ngx_http_limit_var_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_limit_var_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_limit_var_ctx_t   *ctx = (ngx_http_limit_var_ctx_t *)data;


    ngx_str_t                   key;

    time_t                     *value;
    ngx_uint_t                  frequency = 0;

    if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
        return NGX_ERROR;
    }

    if (key.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    value = ngx_flathash_get(ctx->hash, &key);

    ngx_shmtx_lock(&ctx->mutex);

    /* intreting only a less 16 bit of state */

    /* have activity in this second */
    if ((*value & 0xFFFF) == (ngx_time() & 0xFFFF)) {
	frequency = (ngx_uint_t)*value >> 16;
    }

    *value = (frequency + 1) << 16 | (ngx_time() & 0xFFFF);

    ngx_shmtx_unlock(&ctx->mutex);

    if (frequency > ctx->rate) {
	goto outcast;
    }

    v->not_found = 1;
    return NGX_OK;

  outcast:

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
		  "limiting requests, excess %d",
		  frequency);


    v->data = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%d", frequency) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_limit_var_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_var_ctx_t  *octx = data;

    ngx_http_limit_var_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ngx_strcmp(ctx->key.value.data, octx->key.value.data) != 0) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_req \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value, &octx->key.value);
            return NGX_ERROR;
        }

        ctx->hash = octx->hash;

        return NGX_OK;
    }

    ctx->mutex.lock = (ngx_atomic_t *) shm_zone->shm.addr;

    ctx->hash = (ngx_flathash_t *) ((u_char *)shm_zone->shm.addr + sizeof(ngx_atomic_t));

    /* value of hash is a time_t */

    if (ngx_flathash_init(ctx->hash, sizeof(time_t), ctx->size) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_http_limit_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                    *p;
    size_t                     size, len;
    ngx_str_t                 *value, name, s;
    ngx_int_t                  rate;
    ngx_uint_t                 i;
    ngx_shm_zone_t            *shm_zone;
    ngx_http_variable_t       *var;
    ngx_http_limit_var_ctx_t  *ctx;

    ngx_http_compile_complex_value_t   ccv;

    if (sizeof(time_t) < 4) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Sorry. ngx_http_limit_var_module required a system"
			   " with more or equal 32 bit for time_t");
        return NGX_CONF_ERROR;
    }



    value = cf->args->elts;

    ctx = NULL;
    size = 0;
    rate = 1;
    name.len = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p) {
                name.len = p - name.data;

                p++;

                s.len = value[i].data + value[i].len - p;
                s.data = p;

                size = ngx_atoi(s.data, s.len);
                if ((ngx_int_t)size != NGX_ERROR && size > 769) {
                    continue;
                }
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {

            len = value[i].len;
            p = value[i].data + len - 3;

            if (ngx_strncmp(p, "r/s", 3) == 0) {
                len -= 3;
            }

            rate = ngx_atoi(value[i].data + 5, len - 5);
            if (rate <= NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (value[i].data[0] == '$') {

            value[i].len--;
            value[i].data++;

            ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_var_ctx_t));
            if (ctx == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[1];
            ccv.complex_value = &ctx->key;
            ccv.zero = 1;
            ccv.conf_prefix = 1;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0 || size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no var is defined for limit_var_zone \"%V\"",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    ctx->rate = rate;

    ctx->size = size;

    /* value of hash is a time_t */
    size = ngx_flathash_need_memory(sizeof(time_t), size);

    size += sizeof(ngx_atomic_t);

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_limit_var_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                   "limit_var_zone \"%V\" is already bound to var \"%V\"",
                   &value[1], &ctx->key.value);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_limit_var_init_zone;
    shm_zone->data = ctx;

    s.len = sizeof("limit_var_") - 1 + name.len;
    s.data = ngx_palloc(cf->pool, s.len);
    if (s.data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_sprintf(s.data, "limit_var_%V", &name);

    var = ngx_http_add_variable(cf, &s, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_limit_var_variable;
    var->data = (uintptr_t) ctx;

    return NGX_CONF_OK;
}
