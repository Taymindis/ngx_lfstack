/**
* @file   ngx_http_lfstack_module.c
* @author taymindis <cloudleware2015@gmail.com>
* @date   Sun JAN 28 12:06:52 2018
*
* @brief  A ngx_lfstack module for Nginx.
*
* @section LICENSE
*
* Copyright (c) 2018, Taymindis <cloudleware2015@gmail.com>
*
* This module is licensed under the terms of the BSD license.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, this
*    list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <lfsaq/lfstack.h>

#define MODULE_NAME "ngx_lfstack"
#define MAX_DEQ_TRY 1000
#define MAX_SIZE_DIGIT_TRNFM 128
#define LFSTACK_DATA_FILE "ngx_lfstack.txt"

/*Put data above to make malloc in one time*/
typedef struct {
	u_char     *data;
	size_t      len;
} ngx_lfstack_msg_t;

typedef struct {
	ssize_t enq_cnt;
	ssize_t deq_cnt;
	lfstack_t s;
} ngx_lfstack_t;

typedef struct {
	ngx_str_node_t sn;
	void       *value;
} ngx_http_lfstack_value_node_t;

typedef struct {
	ngx_rbtree_t  rbtree;
	ngx_rbtree_node_t sentinel;
	ngx_slab_pool_t *shpool;
} ngx_http_lfstack_shm_t;

typedef struct {
	ngx_str_t name;
	ngx_http_lfstack_shm_t *shared_mem;
} ngx_http_lfstack_shm_ctx_t;

typedef struct {
	ngx_flag_t is_cache_defined;
	ngx_http_lfstack_shm_ctx_t *shm_ctx;
	ngx_array_t                     *_stack_names;
#ifndef NGX_LFSTACK_DISABLE_STORING
	ngx_str_t saved_path;
	ngx_str_t split_delim;
	ngx_array_t *datachain;
#endif
} ngx_http_lfstack_main_conf_t;

typedef struct {
	ngx_http_complex_value_t target_s_name$;
	/*HEAD METHOD for get stack info*/
	/*GET METHOD for pop*/
	/*POST/PUT METHOD for push*/
} ngx_http_lfstack_loc_conf_t;

typedef struct {
	unsigned done: 1;
	unsigned waiting_more_body: 1;
	ngx_int_t rc;
	ngx_http_lfstack_shm_t *shared_mem;
	union {
		ngx_str_t payload;
		ngx_str_t response;
	};
	ngx_http_request_t *r;
	ngx_str_t target_s_name;
	ngx_lfstack_t *_targeted_s;
} ngx_http_lfstack_ctx_t;

static ngx_int_t ngx_http_lfstack_pre_configuration(ngx_conf_t *cf);
static ngx_int_t ngx_http_lfstack_post_configuration(ngx_conf_t *cf);
static void *ngx_http_lfstack_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_lfstack_init_main_conf(ngx_conf_t *cf, void *conf);
static void * ngx_http_lfstack_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_lfstack_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char* ngx_http_lfstack_set_shm_sz_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_lfstack_target_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_lfstack_data_backup_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_lfstack_module_init(ngx_cycle_t *cycle);
static void ngx_http_lfstack_module_exit(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_lfstack_rewrite_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_lfstack_precontent_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_lfstack_shm_init(ngx_shm_zone_t *shm_zone, void *data);

static void ngx_http_lfstack_client_body_handler(ngx_http_request_t *r);
static void ngx_http_lfstack_output_filter(ngx_http_request_t *r);
static void ngx_http_lfstack_process(ngx_http_request_t *r, ngx_http_lfstack_ctx_t *ctx);
#if (NGX_THREADS) //&& (nginx_version > 1013003)
static void ngx_http_lfstack_process_t_handler(void *data, ngx_log_t *log);
static void ngx_http_lfstack_after_t_handler(ngx_event_t *ev);
#endif

// static ngx_int_t ngx_lfstack_check_create_dir(const u_char *path);
static inline void* ngx_lfstack_alloc(void *pl, size_t sz) {
	return ngx_slab_alloc( ((ngx_http_lfstack_shm_t*)pl)->shpool, sz);
}

static inline void ngx_lfstack_free(void *pl, void *ptr) {
	ngx_slab_free( ((ngx_http_lfstack_shm_t*)pl)->shpool, ptr);
}

/** strstr with known length **/
static u_char* ngx_lfstack_get_if_contain(u_char *s1, u_char *e1, u_char *s2, size_t s2_len ) {
	u_char *s3;
	while ( ( s3 = ngx_strlchr(s1, e1, *s2) ) ) {
		if ( ngx_strncmp(s3, s2, s2_len) == 0)  {
			return s3;
		}
		s1 = ++s3;
	}
	return NULL;
}

/**
 * This module provided directive.
 */
static ngx_command_t ngx_http_lfstack_commands[] = {
	{
		ngx_string("ngx_lfstack_memory_allocate"), /* For Share memory Capacity */
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_http_lfstack_set_shm_sz_cmd,
		NGX_HTTP_MAIN_CONF_OFFSET,
		0,
		NULL
	},
	{
		ngx_string("ngx_lfstack_name"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_array_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_lfstack_main_conf_t, _stack_names),
		NULL
	},
	{
		ngx_string("ngx_lfstack_target"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_http_lfstack_target_cmd,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("ngx_lfstack_backup"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE12,
		ngx_http_lfstack_data_backup_cmd,
		NGX_HTTP_MAIN_CONF_OFFSET,
		0,
		NULL
	},
	ngx_null_command /* command termination */
};

// static ngx_shm_zone_t *bk_shm_zone;
static const char* lfstack_head_keys[] = {"stack_name", "stack_size", "push_cnt", "pop_cnt", NULL};
#define HEADER_KEY_STACK_NAME 0
#define HEADER_KEY_STACK_SIZE 1
#define HEADER_KEY_STACK_PUSH 2
#define HEADER_KEY_STACK_POP 3

/* The module context. */
static ngx_http_module_t ngx_http_lfstack_module_ctx = {
	ngx_http_lfstack_pre_configuration, /* preconfiguration */
	ngx_http_lfstack_post_configuration, /* postconfiguration */

	ngx_http_lfstack_create_main_conf,  /* create main configuration */
	ngx_http_lfstack_init_main_conf, /* init main configuration */

	NULL, /* create server configuration */
	NULL, /* merge server configuration */

	ngx_http_lfstack_create_loc_conf, /* create location configuration */
	ngx_http_lfstack_merge_loc_conf /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_lfstack_module = {
	NGX_MODULE_V1,
	&ngx_http_lfstack_module_ctx, /* module context */
	ngx_http_lfstack_commands, /* module directives */
	NGX_HTTP_MODULE, /* module type */
	NULL, /* init master */
	ngx_http_lfstack_module_init, /* init module */
	NULL, /* init process */
	NULL, /* init thread */
	NULL, /* exit thread */
	NULL, /* exit process */
	ngx_http_lfstack_module_exit, /* exit master */
	NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_lfstack_pre_configuration(ngx_conf_t *cf) {
#if (NGX_THREADS)
	ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,  "lfstack, %s", " with aio threads feature");
#endif
	return NGX_OK;
}

static ngx_int_t
ngx_http_lfstack_post_configuration(ngx_conf_t *cf) {
	ngx_http_lfstack_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_lfstack_module);

	if (mcf != NULL ) {
		ngx_http_handler_pt        *h;
		ngx_http_core_main_conf_t  *cmcf;

		cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

		h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
		if (h == NULL) {
			return NGX_ERROR;
		}

		*h = ngx_http_lfstack_rewrite_handler;

		/***Enable pre content phase for apps concurrent processing request layer, NGX_DONE and wait for finalize request ***/
#if (nginx_version > 1013003)
		ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "lfstack, %s", "USING NGX_HTTP_PRECONTENT_PHASE");
		h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
#else  /**Access Phase is the only last phase for multi thread**/
		ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "lfstack, %s", "USING NGX_HTTP_ACCESS_PHASE");
		h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
#endif
		if (h == NULL) {
			return NGX_ERROR;
		}

		*h = ngx_http_lfstack_precontent_handler;
	}

	/*** Default Init for shm with 1M if pool is empty***/
	if (mcf != NULL && !mcf->is_cache_defined ) {
		ngx_conf_log_error(NGX_LOG_DEBUG, cf,   0, "lfstack, %s", "Init Default Share memory with 10mb");
		ngx_str_t default_size = ngx_string("10M");

		ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &mcf->shm_ctx->name, ngx_parse_size(&default_size), &ngx_http_lfstack_module);
		if (shm_zone == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "lfstack, %s", "Unable to allocate size");
			return NGX_ERROR;
		}

		shm_zone->init = ngx_http_lfstack_shm_init;
		shm_zone->data = mcf->shm_ctx;
	}

	return NGX_OK;
}

static void *
ngx_http_lfstack_create_main_conf(ngx_conf_t *cf) {
	ngx_http_lfstack_main_conf_t *mcf;
	mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lfstack_main_conf_t));
	if (mcf == NULL) {
		return NGX_CONF_ERROR;
	}

	mcf->shm_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_lfstack_shm_ctx_t));

	if (mcf->shm_ctx == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_str_set(&mcf->shm_ctx->name , "ngx_lfstack_shm_capacity");

	mcf->shm_ctx->shared_mem = NULL;
	mcf->is_cache_defined = 0;
	mcf->_stack_names = NGX_CONF_UNSET_PTR;

#ifndef NGX_LFSTACK_DISABLE_STORING
	mcf->datachain = NGX_CONF_UNSET_PTR;
	/* Although by default is 0, just in case */
	mcf->split_delim.len = 0;
	mcf->saved_path.len = 0;
#endif

	return mcf;
}

static char *
ngx_http_lfstack_init_main_conf(ngx_conf_t *cf, void *conf) {
	return NGX_CONF_OK;
}


static char*
ngx_http_lfstack_set_shm_sz_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t                      *values;
	ngx_http_lfstack_main_conf_t *mcf = conf;
	ngx_shm_zone_t *shm_zone;
	ngx_int_t pg_size;

	values = cf->args->elts;

	pg_size = ngx_parse_size(&values[1]);

	if (pg_size == NGX_ERROR) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "lfstack, %s", "Invalid cache size, please specify like 1m, 1000m, 9000M or etc.");
		return NGX_CONF_ERROR;
	}


	shm_zone = ngx_shared_memory_add(cf, &mcf->shm_ctx->name, pg_size, &ngx_http_lfstack_module);
	if (shm_zone == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "lfstack, %s", "Unable to allocate apps defined size");
		return NGX_CONF_ERROR;
	}
	mcf->is_cache_defined = 1;
	shm_zone->init = ngx_http_lfstack_shm_init;
	shm_zone->data = mcf->shm_ctx;

	return NGX_CONF_OK;
}

static void *
ngx_http_lfstack_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_lfstack_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lfstack_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	/*lfstack Init*/
	ngx_memzero(&conf->target_s_name$, sizeof(ngx_http_complex_value_t));

	return conf;
}


static char *
ngx_http_lfstack_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	// ngx_http_lfstack_loc_conf_t *prev = parent;
	// ngx_http_lfstack_loc_conf_t *conf = child;

	// if (conf->target_s_name$.len == 0) {
	// 	conf->target_s_name$ = prev->target_s_name$;
	// }

	return NGX_CONF_OK;
}

ngx_int_t
ngx_http_lfstack_shm_init(ngx_shm_zone_t *shm_zone, void *data) {
	size_t                    len;
	ngx_http_lfstack_shm_ctx_t *oshm = data;
	ngx_http_lfstack_shm_ctx_t *nshm = shm_zone->data;
	ngx_slab_pool_t *shpool;

	if (oshm) {
		nshm->name = oshm->name;
		nshm->shared_mem = oshm->shared_mem;
		return NGX_OK;
	}

	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

	if (shm_zone->shm.exists) {
		shm_zone->data = shpool->data;
		return NGX_OK;
	}

	nshm->shared_mem = ngx_slab_alloc(shpool, sizeof(ngx_http_lfstack_shm_t));
	ngx_rbtree_init(&nshm->shared_mem->rbtree, &nshm->shared_mem->sentinel, ngx_str_rbtree_insert_value);

	nshm->shared_mem->shpool = shpool;

	len = sizeof(" in nginx lfstack session shared cache \"\"") + shm_zone->shm.name.len;

	nshm->shared_mem->shpool->log_ctx = ngx_slab_alloc(nshm->shared_mem->shpool, len);
	if (nshm->shared_mem->shpool->log_ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_sprintf(nshm->shared_mem->shpool->log_ctx, " in nginx lfstack session shared cache \"%V\"%Z",
	            &shm_zone->shm.name);

	nshm->shared_mem->shpool->log_nomem = 0;

	return NGX_OK;
}

static char *
ngx_http_lfstack_target_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_lfstack_loc_conf_t *lflcf = conf;
	ngx_str_t                         *value;
	ngx_http_compile_complex_value_t   ccv;

	if (lflcf->target_s_name$.value.len != 0) {
		return "is duplicate";
	}

	value = cf->args->elts;

	if (value[1].len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "lfstack, %s", "no stack name given ");
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[1];
	ccv.complex_value = &lflcf->target_s_name$;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static char *
ngx_http_lfstack_data_backup_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_lfstack_main_conf_t *lfmcf = conf;
	ngx_str_t                    *value;

	value = cf->args->elts;

	if (lfmcf->datachain == NGX_CONF_UNSET_PTR) {
		lfmcf->datachain = ngx_array_create(cf->pool, 1024 /*Initial buffer*/, sizeof(ngx_str_t));
	} else {
		return "is duplicate";
	}

	if ( cf->args->nelts == 3 ) {
		lfmcf->saved_path.data = value[2].data;
		lfmcf->saved_path.len = ngx_strlen(value[2].data);
	}

	lfmcf->split_delim.data = value[1].data;
	lfmcf->split_delim.len = ngx_strlen(value[1].data);

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_lfstack_rewrite_handler(ngx_http_request_t *r) {
	ngx_http_lfstack_loc_conf_t  *lcf = ngx_http_get_module_loc_conf(r, ngx_http_lfstack_module);
	ngx_http_lfstack_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_lfstack_module);
	ngx_http_lfstack_ctx_t *ctx;
	ngx_int_t rc;
	ngx_str_t target_stack_key;
	ngx_lfstack_t *targeted_q;

	if (mcf == NULL) {
		// ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "lfstack config not found");
		targeted_q = NULL;
	} else if (ngx_http_complex_value(r, &lcf->target_s_name$, &target_stack_key) != NGX_OK) {
		// ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s", "No target stack set");
		targeted_q = NULL;
	} else if (target_stack_key.len == 0) {
		// ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s", " No stack found ");
		targeted_q = NULL;
	} else {
		uint32_t hash = ngx_crc32_long(target_stack_key.data, target_stack_key.len);
		ngx_http_lfstack_shm_t *_shm = mcf->shm_ctx->shared_mem;
		ngx_http_lfstack_value_node_t *vnt = (ngx_http_lfstack_value_node_t *)
		                                     ngx_str_rbtree_lookup(&_shm->rbtree, &target_stack_key, hash);
		if (vnt) {
			targeted_q = vnt->value;
		} else {
			targeted_q = NULL;
		}
	}

	if (r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH)) {
		// r->request_body_in_single_buf = 1;
		// r->request_body_in_clean_file = 1;
		// r->request_body_in_persistent_file = 1;
		ctx = ngx_http_get_module_ctx(r, ngx_http_lfstack_module);

		if (ctx != NULL) {
			if (ctx->done) {
				/***Done Reading***/
				return NGX_DECLINED;
			}
			return NGX_DONE;
		}

		/* calloc, has init with 0 value*/
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_lfstack_ctx_t));

		if (ctx == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Insufficient Memory to create ngx_http_lfstack_ctx_t");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ctx->r = r;
		ctx->rc = NGX_CONF_UNSET;
		ctx->_targeted_s = targeted_q;
		ctx->target_s_name.data = target_stack_key.data;
		ctx->target_s_name.len = target_stack_key.len;
		ngx_http_set_ctx(r, ctx, ngx_http_lfstack_module);

		if (ctx->_targeted_s == NULL) {
			return NGX_DECLINED;
		}

		/****Reading Body Request ****/
		rc = ngx_http_read_client_request_body(r, ngx_http_lfstack_client_body_handler);

		if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
        (nginx_version >= 1003000 && nginx_version < 1003009)
			r->main->count--;
#endif
			return rc;
		}

		if (rc == NGX_AGAIN) {
			ctx->waiting_more_body = 1;
			return NGX_DONE;
		}

		return NGX_DECLINED;
	} else {
		ctx = ngx_http_get_module_ctx(r, ngx_http_lfstack_module);
		if (ctx == NULL) {
			/* calloc, has init with 0 value*/
			ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_lfstack_ctx_t));
			if (ctx == NULL) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Insufficient Memory to create ngx_http_lfstack_ctx_t");
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			ctx->r = r;
			ctx->rc = NGX_CONF_UNSET;
			ctx->_targeted_s = targeted_q;
			ctx->target_s_name.data = target_stack_key.data;
			ctx->target_s_name.len = target_stack_key.len;
			ngx_http_set_ctx(r, ctx, ngx_http_lfstack_module);
			if (ctx->_targeted_s == NULL) {
				return NGX_DECLINED;
			}
		}
		return NGX_DECLINED;
	}
}

static void
ngx_http_lfstack_client_body_handler(ngx_http_request_t *r) {
	ngx_http_lfstack_ctx_t *ctx;
	ctx = ngx_http_get_module_ctx(r, ngx_http_lfstack_module);
	ctx->done = 1;

#if defined(nginx_version) && nginx_version >= 8011
	r->main->count--;
#endif
	/* waiting_more_body my rewrite phase handler */
	if (ctx->waiting_more_body) {
		ctx->waiting_more_body = 0;
		ngx_http_core_run_phases(r);
	}
}

/**
 * Pre Content handler.
 * @param r
 *   Pointer to the request structure. See http_request.h.
 * @return
 *   The status of the response generation.
 */
static ngx_int_t
ngx_http_lfstack_precontent_handler(ngx_http_request_t *r) {
	// ngx_http_lfstack_loc_conf_t  *lcf = ngx_http_get_module_loc_conf(r, ngx_http_lfstack_module);
	ngx_http_lfstack_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_lfstack_module);
	ngx_http_lfstack_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_lfstack_module);

	if (ctx == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "error while processing request");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	} else if (ctx->_targeted_s == NULL) {
		/** Not for ngx lfstack handler, decline it**/
		return NGX_DECLINED;
	}

	if (ctx->rc == NGX_CONF_UNSET) {
		goto new_task;
	}

	ngx_http_lfstack_output_filter(r);
// #if (nginx_version > 1013003)
	return NGX_DONE;
// #else
	// return NGX_OK;
// #endif

new_task:

	ctx->shared_mem = mcf->shm_ctx->shared_mem;

	/***Set to default incase link library does not return anything ***/
	ctx->rc = NGX_HTTP_INTERNAL_SERVER_ERROR;

	if (r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH)) {
		u_char              *p, *buf = NULL;
		ngx_chain_t         *cl;
		size_t               len;
		ngx_buf_t           *b;

		if (r->request_body == NULL || r->request_body->bufs == NULL) {
			goto REQUEST_BODY_DONE;
		}

		if (r->request_body->bufs->next != NULL) {
			len = 0;
			for (cl = r->request_body->bufs; cl; cl = cl->next) {
				b = cl->buf;
				if (b->in_file) {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "insufficient client_body_buffer_size");
					return NGX_HTTP_INTERNAL_SERVER_ERROR;
				}
				len += b->last - b->pos;
			}
			if (len == 0) {
				goto REQUEST_BODY_DONE;
			}

			buf = ngx_palloc(r->pool, len );
			if (buf == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "insufficient memory.");
				goto REQUEST_BODY_DONE;
			}

			p = buf;
			for (cl = r->request_body->bufs; cl; cl = cl->next) {
				p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
			}
		} else {
			b = r->request_body->bufs->buf;
			if ((len = ngx_buf_size(b)) == 0) {
				goto REQUEST_BODY_DONE;
			}
			buf = ngx_palloc(r->pool, len );
			ngx_memcpy(buf, b->pos, len);
		}
		/************End REading ****************/

REQUEST_BODY_DONE:
		if (buf /*If got request body*/) {
			// ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "request_content=%*s \n", len, buf);
			ctx->payload.data = buf;
			ctx->payload.len = len;
		} else {
			// ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s\n", "No data to push");
			return NGX_HTTP_BAD_REQUEST;
		}
	} else { //if (!(r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH))) {
		if (ngx_http_discard_request_body(r) != NGX_OK) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

#if (NGX_THREADS) //&& (nginx_version > 1013003)
	ngx_thread_pool_t         *tp;
	ngx_http_core_loc_conf_t     *clcf;

	clcf  = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	tp = clcf->thread_pool;

	if (tp == NULL) {
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "lfstack is processing single thread only, specify \"aio threads;\" in server/loc block for concurrent request");
		goto single_thread;
	}

	ngx_thread_task_t *task = ngx_thread_task_alloc(r->pool, sizeof(ngx_http_request_t));
	ngx_memcpy(task->ctx, r, sizeof(ngx_http_request_t));
	task->handler = ngx_http_lfstack_process_t_handler;
	task->event.data = r;
	task->event.handler = ngx_http_lfstack_after_t_handler;

	if (ngx_thread_task_post(tp, task) != NGX_OK) {
		return NGX_ERROR;
	}
	r->main->blocked++;
	r->aio = 1;
	return NGX_DONE;
single_thread:
#endif

	// ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, " Processing lfstack ");

	ngx_http_lfstack_process(r, ctx);

	ngx_http_lfstack_output_filter(r);

// #if (nginx_version > 1013003)
	return NGX_DONE;
// #else
	// return NGX_OK;
// #endif
}

static void
ngx_http_lfstack_process(ngx_http_request_t *r, ngx_http_lfstack_ctx_t *ctx)
{
	ngx_lfstack_msg_t *smsg;
	u_char *rs;
	ngx_uint_t i;
	ngx_str_t *payload = &ctx->payload;
	ngx_table_elt_t *h;

	if (r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH)) {

		smsg = ngx_slab_alloc(ctx->shared_mem->shpool, sizeof(ngx_lfstack_msg_t) + payload->len );

		if (smsg == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, " No enough share memory given, expand the share memory capacity");
			ctx->rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			return;
		}

		smsg->data = ((u_char*)smsg) + sizeof(ngx_lfstack_msg_t);
		smsg->len = payload->len;
		ngx_memcpy(smsg->data, payload->data, payload->len);
		payload->len = 0; // clear the data, enqueu does not need to response any content

		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, " %s", "pushing" );
		lfstack_push(&ctx->_targeted_s->s, smsg);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, " %s", "pushing done" );
		ngx_atomic_fetch_add(&ctx->_targeted_s->enq_cnt, 1);

		ctx->rc = NGX_HTTP_ACCEPTED;

	} else if ( r->method & NGX_HTTP_HEAD ) {
		for (i = 0; lfstack_head_keys[i]; i++) {
			h = ngx_list_push(&r->headers_out.headers);
			if (h == NULL) {
				ctx->rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
				return;
			}
			h->hash = 1; /*to mark HTTP output headers show set 1, show missing set 0*/
			h->key.len = ngx_strlen(lfstack_head_keys[i]);
			h->key.data = ngx_palloc(r->pool, h->key.len * sizeof(u_char));
			ngx_memcpy(h->key.data, lfstack_head_keys[i], h->key.len);

			switch (i) {
			case HEADER_KEY_STACK_NAME:
				h->value.data = ctx->target_s_name.data;
				h->value.len = ctx->target_s_name.len;
				break;
			case HEADER_KEY_STACK_SIZE:
				h->value.data = ngx_pcalloc(r->pool, MAX_SIZE_DIGIT_TRNFM * sizeof(u_char));
				ngx_snprintf(h->value.data, MAX_SIZE_DIGIT_TRNFM - 1,  "%z", lfstack_size(&ctx->_targeted_s->s) );
				h->value.len = ngx_strlen(h->value.data);
				break;
			case HEADER_KEY_STACK_PUSH:
				h->value.data = ngx_pcalloc(r->pool, MAX_SIZE_DIGIT_TRNFM * sizeof(u_char));
				ngx_snprintf(h->value.data, MAX_SIZE_DIGIT_TRNFM - 1,  "%z", ctx->_targeted_s->enq_cnt );
				h->value.len = ngx_strlen(h->value.data);
				break;
			case HEADER_KEY_STACK_POP:
				h->value.data = ngx_pcalloc(r->pool, MAX_SIZE_DIGIT_TRNFM * sizeof(u_char));
				ngx_snprintf(h->value.data, MAX_SIZE_DIGIT_TRNFM - 1,  "%z", ctx->_targeted_s->deq_cnt );
				h->value.len = ngx_strlen(h->value.data);
				break;
			}
		}

		ctx->rc = NGX_HTTP_NO_CONTENT;

	} else {
		/** PROCESSING Pop, 10 sec trying**/
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, " %s", "poping" );
		for (i = 0; i < MAX_DEQ_TRY; i++) {
			if ( (smsg = lfstack_pop(&ctx->_targeted_s->s)) ) {
				ngx_atomic_fetch_add(&ctx->_targeted_s->deq_cnt, 1);
				goto QMSG_FOUND;
			}
			ngx_msleep(10);
		}

		ctx->rc = NGX_HTTP_NO_CONTENT;
		return;
QMSG_FOUND:
		// ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, " Content %*s ", smsg->len, smsg->data);
		if (smsg->len) {
			rs = ngx_palloc(r->pool, smsg->len);
			ngx_memcpy(rs, smsg->data, smsg->len);
			ctx->response.data = rs;
			ctx->response.len = smsg->len;
			ngx_slab_free(ctx->shared_mem->shpool, smsg);
			ctx->rc = NGX_HTTP_OK;
		}
	}
}

#if (NGX_THREADS) //&& (nginx_version > 1013003)
static void
ngx_http_lfstack_process_t_handler(void *data, ngx_log_t *log)
{
	ngx_http_request_t *r = data;
	ngx_http_lfstack_ctx_t *ctx;
	ngx_lfstack_msg_t *smsg;
	u_char *rs;
	ngx_uint_t i;
	ngx_str_t *payload;
	ngx_table_elt_t *h;

	ctx = ngx_http_get_module_ctx(r, ngx_http_lfstack_module);
	payload = &ctx->payload;

	if (r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH)) {

		smsg = ngx_slab_alloc(ctx->shared_mem->shpool, sizeof(ngx_lfstack_msg_t) + payload->len );

		if (smsg == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, " No enough share memory given, expand the share memory capacity");
			ctx->rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			return;
		}

		smsg->data = ((u_char*)smsg) + sizeof(ngx_lfstack_msg_t);
		smsg->len = payload->len;
		ngx_memcpy(smsg->data, payload->data, payload->len);
		payload->len = 0;

		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, " %s", "pushing" );
		lfstack_push(&ctx->_targeted_s->s, smsg);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, " %s", "pushing done" );
		ngx_atomic_fetch_add(&ctx->_targeted_s->enq_cnt, 1);

		ctx->rc = NGX_HTTP_ACCEPTED;

	} else if ( r->method & NGX_HTTP_HEAD ) {
		for (i = 0; lfstack_head_keys[i]; i++) {
			h = ngx_list_push(&r->headers_out.headers);
			if (h == NULL) {
				ctx->rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
				return;
			}
			h->hash = 1; /*to mark HTTP output headers show set 1, show missing set 0*/
			h->key.len = ngx_strlen(lfstack_head_keys[i]);
			h->key.data = ngx_palloc(r->pool, h->key.len * sizeof(u_char));
			ngx_memcpy(h->key.data, lfstack_head_keys[i], h->key.len);

			switch (i) {
			case HEADER_KEY_STACK_NAME:
				h->value.data = ctx->target_s_name.data;
				h->value.len = ctx->target_s_name.len;
				break;
			case HEADER_KEY_STACK_SIZE:
				h->value.data = ngx_pcalloc(r->pool, MAX_SIZE_DIGIT_TRNFM * sizeof(u_char));
				ngx_snprintf(h->value.data, MAX_SIZE_DIGIT_TRNFM - 1,  "%z", (ssize_t) lfstack_size(&ctx->_targeted_s->s) );
				h->value.len = ngx_strlen(h->value.data);
				break;
			case HEADER_KEY_STACK_PUSH:
				h->value.data = ngx_pcalloc(r->pool, MAX_SIZE_DIGIT_TRNFM * sizeof(u_char));
				ngx_snprintf(h->value.data, MAX_SIZE_DIGIT_TRNFM - 1,  "%z", ctx->_targeted_s->enq_cnt );
				h->value.len = ngx_strlen(h->value.data);
				break;
			case HEADER_KEY_STACK_POP:
				h->value.data = ngx_pcalloc(r->pool, MAX_SIZE_DIGIT_TRNFM * sizeof(u_char));
				ngx_snprintf(h->value.data, MAX_SIZE_DIGIT_TRNFM - 1,  "%z", ctx->_targeted_s->deq_cnt );
				h->value.len = ngx_strlen(h->value.data);
				break;
			}
		}

		ctx->rc = NGX_HTTP_NO_CONTENT;

	} else {
		/** PROCESSING Pop, 10 sec trying**/
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, " %s", "poping" );
		for (i = 0; i < MAX_DEQ_TRY; i++) {
			if ( (smsg = lfstack_pop(&ctx->_targeted_s->s)) ) {
				ngx_atomic_fetch_add(&ctx->_targeted_s->deq_cnt, 1);
				goto QMSG_FOUND;
			}
			ngx_msleep(10);
		}

		ctx->rc = NGX_HTTP_NO_CONTENT;
		return;


QMSG_FOUND:
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, " Message found ");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, " Content %*s ", smsg->len, smsg->data);


		if (smsg->len) {
			rs = ngx_palloc(r->pool, smsg->len);
			ngx_memcpy(rs, smsg->data, smsg->len);
			ctx->response.data = rs;
			ctx->response.len = smsg->len;
			ngx_slab_free(ctx->shared_mem->shpool, smsg);
			ctx->rc = NGX_HTTP_OK;
		}
	}
}

static void
ngx_http_lfstack_after_t_handler(ngx_event_t *ev) {
	ngx_connection_t    *c;
	ngx_http_request_t  *r;

	r = ev->data;
	c = r->connection;

	ngx_http_set_log_request(c->log, r);

	r->main->blocked--;
	r->aio = 0;

	r->write_event_handler(r);
	ngx_http_run_posted_requests(c);
}
#endif

static void
ngx_http_lfstack_output_filter(ngx_http_request_t *r) {
	ngx_int_t rc;
	ngx_chain_t out;
	ngx_http_lfstack_ctx_t *ctx;
	ngx_str_t *response;
	size_t resp_len;
	ngx_buf_t *b;

	ctx = ngx_http_get_module_ctx(r, ngx_http_lfstack_module);

	if (ctx == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Session is not valid");
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	if (ctx->rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Internal Server error");
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	response = &ctx->response;

	r->headers_out.status = ctx->rc;

	r->headers_out.content_type.len = sizeof("text/plain") - 1;
	r->headers_out.content_type.data = (u_char *) "text/plain";

	/**Response Content***/
	if ( (resp_len = response->len) ) {
		r->headers_out.content_length_n = resp_len;
		rc = ngx_http_send_header(r); /* Send the headers */
		if (rc == NGX_ERROR) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "response processing failed.");
			// ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;

		}
		b = ngx_create_temp_buf(r->pool, resp_len);
		b->last = ngx_copy(b->last, response->data, resp_len);
		b->memory = 1; /* content is in read-only memory */
		b->last_buf = 1; /* there will be no more buffers in the request */

		/* Insertion in the buffer chain. */
		out.buf = b;
		out.next = NULL; /* just one buffer */

		/* Send the body, and return the status code of the output filter chain. */
		ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
	} else {
		r->headers_out.content_length_n = 0;
		r->header_only = 1;
		ngx_http_finalize_request(r, ngx_http_send_header(r));
	}
}

static ngx_int_t
ngx_http_lfstack_module_init(ngx_cycle_t *cycle) {
	ngx_core_conf_t  *ccf;
	ngx_uint_t i;
	ngx_http_lfstack_main_conf_t *mcf;
	ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_http_module);
	ngx_str_t *s, *stkstr;
	ngx_lfstack_t *_stacks;
	uint32_t hash;
	ngx_http_lfstack_value_node_t *vnt;
	ngx_http_lfstack_shm_t *shm;
	ngx_uint_t has_lfstack_init = 0;
	ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

	if (ccf->worker_processes > 1) {
		ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "%s", "support more than 1 worker_processes may slow down the lfstack performance");
	}

	mcf = ctx->main_conf[ngx_http_lfstack_module.ctx_index];

	if (mcf->_stack_names == NGX_CONF_UNSET_PTR) {
		/** No lfstack triggered **/
		return NGX_OK;
	}

	shm = mcf->shm_ctx->shared_mem;

#if (NGX_THREADS)
	ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, " enabled aio threads for lfstack module ");
#endif

	if (mcf->_stack_names->nelts > 0) {
		stkstr = mcf->_stack_names->elts;

		/**Check the first stack whether has initiliazed lfstack**/
		for (i = 0; i < mcf->_stack_names->nelts; i++) {
			s = stkstr + i;
			hash = ngx_crc32_long(s->data, s->len);
			vnt = (ngx_http_lfstack_value_node_t *) ngx_str_rbtree_lookup(&shm->rbtree, s, hash);
			if (vnt) {
				_stacks = vnt->value;
				if (_stacks != NULL) {
					has_lfstack_init = 1;
					_stacks->s.pl = shm;
				}
			} else {
				break;
			}
		}

		if (has_lfstack_init) {
			goto LFSTACK_INIT_DONE;
		}

		/*** Init lfstack ***/
		ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, " Initializing lfstack ");
		_stacks = ngx_slab_calloc(shm->shpool, mcf->_stack_names->nelts * sizeof(ngx_lfstack_t));
		if (_stacks == NULL) {
			ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, " share memory allocation error ");
			return NGX_ERROR;
		}

		for (i = 0; i < mcf->_stack_names->nelts; i++) {
			s = stkstr + i;
			ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, " Queue name \"%V\"\n", s);

			if (lfstack_init_mf(&_stacks[i].s, shm, ngx_lfstack_alloc, ngx_lfstack_free) == -1) {
				ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, " lfstack Initializing error... ");
				return NGX_ERROR;
			}
			_stacks[i].enq_cnt = 0;
			_stacks[i].deq_cnt = 0;

			ngx_http_lfstack_value_node_t *vnt = (ngx_http_lfstack_value_node_t *)
			                                     ngx_slab_alloc(shm->shpool, sizeof(ngx_http_lfstack_value_node_t));

			if (vnt == NULL) {
				ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, " share memory allocation error ");
				return NGX_ERROR;
			}

			ngx_str_t *str_key = &(vnt->sn.str);
			str_key->len = s->len;
			str_key->data = (u_char*) ngx_slab_alloc(shm->shpool, sizeof(u_char) * (str_key->len + 1) );
			ngx_memcpy(str_key->data, s->data, str_key->len);
			str_key->data[str_key->len] = 0;

			uint32_t hash = ngx_crc32_long(str_key->data, str_key->len);
			vnt->value = _stacks + i;
			vnt->sn.node.key = hash;
			ngx_rbtree_insert(&shm->rbtree, &vnt->sn.node);
		}

#ifndef NGX_LFSTACK_DISABLE_STORING
		u_char *filecontent, *p, *pflip, *pend, *store_file_path;
		uintptr_t *arrp;
		ngx_array_t *qarr;
		ngx_str_t delim, delim_stkkey, delim_msgkey;
		ngx_fd_t readfd;
		ngx_file_info_t fi;
		off_t store_sz;
		ngx_uint_t n;
		ngx_lfstack_msg_t *smsg;

		if (mcf->saved_path.len == 0) {
			p = store_file_path = (u_char*) ngx_pcalloc(cycle->pool, cycle->conf_prefix.len + sizeof(LFSTACK_DATA_FILE));
			p = ngx_copy(p, cycle->conf_prefix.data, cycle->conf_prefix.len);
			p = ngx_copy(p, LFSTACK_DATA_FILE, sizeof(LFSTACK_DATA_FILE));
		} else {
			store_file_path = mcf->saved_path.data;
		}

		readfd = ngx_open_file(store_file_path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
		if (readfd != NGX_INVALID_FILE) {
			if (ngx_fd_info(readfd, &fi) != NGX_FILE_ERROR) {
				if ( (store_sz = ngx_file_size(&fi) ) ) {
					ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, " read file size %O bytes ", store_sz);
					filecontent = (u_char*) ngx_pcalloc(cycle->pool, store_sz);
					if ( read(readfd, filecontent, store_sz) == -1 ) {
						ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "read backup file \"%s\" failed", store_file_path);
						goto LFSTACK_INIT_DONE;
					} else if (ngx_close_file(readfd) == NGX_FILE_ERROR || ngx_delete_file(store_file_path) == NGX_FILE_ERROR) {
						ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "unable to close / remove data file %s", store_file_path);
					}

					ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "restoring... ");
					/**DECODING**/
					ngx_str_t plain_data;
					ngx_str_t encoded_data;
					encoded_data.len = store_sz;
					encoded_data.data = filecontent;
					ngx_uint_t declen = ngx_base64_decoded_length(store_sz);
					plain_data.len = declen;
					plain_data.data = (u_char*) ngx_pcalloc(cycle->pool, declen );
					ngx_decode_base64(&plain_data, &encoded_data);
					/**DECODING END**/
					// ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "DATA RESTORE \n\n%V ", &plain_data);
					pflip = plain_data.data;
					pend = pflip + plain_data.len;

					/** GET DELIMETER **/
					if ( (p = ngx_lfstack_get_if_contain(pflip, pend, (u_char*) "k@", sizeof("k@") - 1) ) ) {
						delim.len = (p - pflip);
						delim.data = (u_char*) ngx_pcalloc(cycle->pool, delim.len );
						ngx_memcpy(delim.data, pflip, delim.len);
					} else {
						ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "backup restore failed, no key found");
						goto LFSTACK_INIT_DONE;
					}

					delim_msgkey.len = delim_stkkey.len = delim.len + (sizeof("k@") - 1);
					delim_stkkey.data = ngx_pcalloc(cycle->pool, delim.len + (sizeof("k@") - 1));
					delim_msgkey.data = ngx_pcalloc(cycle->pool, delim.len + (sizeof("m@") - 1));
					ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "delim %V", &delim);

					ngx_memcpy(delim_stkkey.data, delim.data, delim.len);
					ngx_memcpy(delim_stkkey.data + delim.len, "k@", (sizeof("k@") - 1));
					ngx_memcpy(delim_msgkey.data, delim.data, delim.len);
					ngx_memcpy(delim_msgkey.data + delim.len, "m@", (sizeof("m@") - 1));

					qarr = ngx_array_create(cycle->pool, 128, sizeof(uintptr_t));

					p = pflip;
					while ( (p = ngx_lfstack_get_if_contain(p, pend, delim_stkkey.data, delim_stkkey.len ) ) ) {
						arrp = ngx_array_push(qarr);
						p = p + delim_stkkey.len;
						*arrp = (uintptr_t) (u_char*) p;
					}

					arrp = (uintptr_t*) qarr->elts;

					for ( n = 0; n < qarr->nelts; n++ ) {
						pflip = (u_char*) arrp[n];
						if ( (n + 1) == qarr->nelts ) {
							pend = plain_data.data + plain_data.len;
						} else {
							pend = (u_char*) arrp[n + 1];
							pend -= delim_stkkey.len;
						}

						for (i = 0; i < mcf->_stack_names->nelts; i++) {
							if ( (p = ngx_lfstack_get_if_contain(pflip, pend, delim_msgkey.data, delim_msgkey.len) ) ) {
								s = stkstr + i;
								if ( s->len == (size_t) (p - pflip) && ngx_strncmp(s->data, pflip, (p - pflip) ) == 0 ) {
									hash = ngx_crc32_long(s->data, s->len);
									vnt = (ngx_http_lfstack_value_node_t *) ngx_str_rbtree_lookup(&shm->rbtree, s, hash);
									if (vnt) {
										_stacks = vnt->value;
										if (_stacks != NULL) {
											pflip = p + delim_msgkey.len;
											while ( (p = ngx_lfstack_get_if_contain(pflip, pend,
											                                        delim_msgkey.data, delim_msgkey.len ) ) ) {
												smsg = ngx_slab_alloc(shm->shpool, sizeof(ngx_lfstack_msg_t) + (p - pflip) );

												if (smsg == NULL) {
													ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, " No enough share memory given, expand the share memory capacity");
													return NGX_ERROR;
												}

												smsg->data = ((u_char*)smsg) + sizeof(ngx_lfstack_msg_t);
												smsg->len = (p - pflip);
												ngx_memcpy(smsg->data, pflip, (p - pflip));
												lfstack_push(&_stacks->s, smsg);
												pflip = p + delim_msgkey.len;
											}
											smsg = ngx_slab_alloc(shm->shpool, sizeof(ngx_lfstack_msg_t) + (pend - pflip) );
											if (smsg == NULL) {
												ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, " No enough share memory given, expand the share memory capacity");
												return NGX_ERROR;
											}
											smsg->data = ((u_char*)smsg) + sizeof(ngx_lfstack_msg_t);
											smsg->len = (pend - pflip);
											ngx_memcpy(smsg->data, pflip, (pend - pflip));
											lfstack_push(&_stacks->s, smsg);
										}
									}
								}
							}
						}
					}

					ngx_pfree(cycle->pool, delim.data);
					ngx_pfree(cycle->pool, delim_stkkey.data);
					ngx_pfree(cycle->pool, delim_msgkey.data);
					ngx_pfree(cycle->pool, filecontent);
					ngx_pfree(cycle->pool, plain_data.data);
					ngx_array_destroy(qarr);
					ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, " backup data %s has been restored ", store_file_path);
				}
			}
		}
		ngx_pfree(cycle->pool, store_file_path);
#endif
	} else {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, " No stack names specified ");
		return NGX_ERROR;
	}

LFSTACK_INIT_DONE:
	ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, " lfstack has successfully Initialized");

	return NGX_OK;
}

static void
ngx_http_lfstack_module_exit(ngx_cycle_t *cycle) {
#ifndef NGX_LFSTACK_DISABLE_STORING
	ngx_http_lfstack_main_conf_t *mcf;
	ngx_http_conf_ctx_t *ctx;
	ngx_http_lfstack_shm_t *shm;
	u_char *p, *store_file_path;
	ngx_str_t *s, *ps, *stkstr, delim_stkkey, delim_msgkey;
	ngx_lfstack_t *_stacks;
	lfstack_t *stack;
	ngx_lfstack_msg_t *smsg;
	uint32_t hash;
	ngx_http_lfstack_value_node_t *vnt;
	ngx_uint_t i;
	off_t store_sz = 0;
	ngx_array_t *datachain;

	ctx = (ngx_http_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_http_module);
	if (ctx == NULL) {
		ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "ngx_http_lfstack_module_exit in error, unable to get config context");
		return;
	}

	mcf = ctx->main_conf[ngx_http_lfstack_module.ctx_index];
	shm = mcf->shm_ctx->shared_mem;
	if (shm == NULL) {
		ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "ngx_http_lfstack_module_exit in error, lfstack data not found");
		return;
	} else if (mcf->datachain == NGX_CONF_UNSET_PTR) {
		goto LFSTACK_MASTER_EXIT;
	} else if ( mcf->split_delim.len == 0) {
		ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "backup failed, no key split found");
		return;
	} else if (mcf->_stack_names->nelts > 0) {
		datachain = mcf->datachain;

		delim_msgkey.len = delim_stkkey.len = mcf->split_delim.len + 2;
		delim_stkkey.data = ngx_pcalloc(cycle->pool, mcf->split_delim.len + 2);
		delim_msgkey.data = ngx_pcalloc(cycle->pool, mcf->split_delim.len + 2);
		ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "mcf->split_delim %V", &mcf->split_delim);

		ngx_memcpy(delim_stkkey.data, mcf->split_delim.data, mcf->split_delim.len);
		ngx_memcpy(delim_stkkey.data + mcf->split_delim.len, "k@", 2);
		ngx_memcpy(delim_msgkey.data, mcf->split_delim.data, mcf->split_delim.len);
		ngx_memcpy(delim_msgkey.data + mcf->split_delim.len, "m@", 2);

		/** Backup stack message **/
		stkstr = mcf->_stack_names->elts;
		for (i = 0; i < mcf->_stack_names->nelts; i++) {
			s = stkstr + i;
			hash = ngx_crc32_long(s->data, s->len);
			vnt = (ngx_http_lfstack_value_node_t *) ngx_str_rbtree_lookup(&shm->rbtree, s, hash);
			if (vnt) {
				_stacks = vnt->value;
				if (_stacks != NULL) {
					stack = &_stacks->s;
					if ( (lfstack_size(stack)) ) {
						if ( ngx_lfstack_get_if_contain(s->data, s->data + s->len, mcf->split_delim.data, mcf->split_delim.len ) ) {
							goto LFSTACK_MASTER_EXIT_WITH_DELIM_CRASH;
						}
						ps = ngx_array_push(datachain);
						ps->data = delim_stkkey.data;
						ps->len = delim_stkkey.len;
						store_sz += delim_stkkey.len;
						ps = ngx_array_push(datachain);
						ps->data = s->data;
						ps->len = s->len;
						store_sz += s->len;
					} else {
						continue;
					}
					while ( (smsg = lfstack_pop(stack)) ) {
						if ( ngx_lfstack_get_if_contain(smsg->data, smsg->data + smsg->len, mcf->split_delim.data, mcf->split_delim.len ) ) {
							goto LFSTACK_MASTER_EXIT_WITH_DELIM_CRASH;
						}
						ps = ngx_array_push(datachain);
						ps->data = delim_msgkey.data;
						ps->len = delim_msgkey.len;
						store_sz += delim_msgkey.len;
						ps = ngx_array_push(datachain);
						ps->data = smsg->data;
						ps->len = smsg->len;
						store_sz += smsg->len;
					}
				}
			}
		}
	} else {
		goto LFSTACK_MASTER_EXIT;
	}

	if ( 0 == datachain->nelts ) {
		ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "no data backup requied");
		goto LFSTACK_MASTER_EXIT;
	}

	ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "backup size %O bytes", store_sz);
	/** Storing data **/
	if (mcf->saved_path.len == 0) {
		p = store_file_path = (u_char*) ngx_pcalloc(cycle->pool, cycle->conf_prefix.len + sizeof(LFSTACK_DATA_FILE));
		p = ngx_copy(p, cycle->conf_prefix.data, cycle->conf_prefix.len);
		p = ngx_copy(p, LFSTACK_DATA_FILE, sizeof(LFSTACK_DATA_FILE));
	} else {
		store_file_path = mcf->saved_path.data;
	}

	FILE *stored_file;
	stored_file = fopen ((char*) store_file_path, "w");
	if (stored_file == NULL) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Error while storing backup data file, unable to create file");
		goto LFSTACK_MASTER_EXIT;
	}

	/** Upside down Stack content, stack content reload with push content the bottom one should be on top, top will be on bottom **/
	u_char *stack_content = ngx_pcalloc(cycle->pool,  store_sz);
	ngx_str_t *strarr = (ngx_str_t *) mcf->datachain->elts;
	ngx_int_t n, keyfound = 0, mark = mcf->datachain->nelts - 1;
	p = stack_content;

	for (n = mark; n >= 0; n--) {
		s = strarr + n;
		if (s->len == delim_stkkey.len &&  ngx_strncmp(s->data, delim_stkkey.data, delim_stkkey.len) == 0) {
			if (keyfound) {
				keyfound = 0;
				mark = n - 1;
				continue;
			}
			p = ngx_copy(p, s->data, s->len);
			p = ngx_copy(p, s[1].data, s[1].len);
			keyfound = 1;
			n = mark;
		} else if (keyfound && s->len == delim_msgkey.len && ngx_strncmp(s->data, delim_msgkey.data, delim_msgkey.len) == 0) {			
			p = ngx_copy(p, s->data, s->len);
			p = ngx_copy(p, s[1].data, s[1].len);
		}
	}
	// ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Data has been upside down %*s", store_sz, stack_content);
	ngx_array_destroy(mcf->datachain);


	/** ENCODING **/
	ngx_str_t encoded_data;
	ngx_str_t plain_data;
	plain_data.data = stack_content;
	plain_data.len = store_sz;


	ngx_uint_t enclen = ngx_base64_encoded_length(plain_data.len);
	encoded_data.data =  (u_char*) ngx_pcalloc(cycle->pool, enclen );
	encoded_data.len =  enclen;
	ngx_encode_base64(&encoded_data, &plain_data);
	/** END ENCODING **/

	if ( fwrite (encoded_data.data, encoded_data.len, 1, stored_file) != 1 ) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Error while storing backup data file, unable to write to file");
	}

	ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Data has been successfully saved to %s", store_file_path);
LFSTACK_MASTER_EXIT:
#endif
	// ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Share memory size is %z", shm->shpool->end -  shm->shpool->start);
	ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "ngx_http_lfstack_module_exit");
	return;
LFSTACK_MASTER_EXIT_WITH_DELIM_CRASH:
	ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "backup failed, stack message data has contain split key, suggest to change unique split key e.g ngx_lfstack_backup <split_key>");
}