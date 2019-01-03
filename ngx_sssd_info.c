#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <dbus/dbus.h>

#define DBUS_SSSD_DESTINATION "org.freedesktop.sssd.infopipe"
#define DBUS_SSSD_TIMEOUT 5000
#define DBUS_INTERFACE_PROPERTIES "org.freedesktop.DBus.Properties"
#define DBUS_PROPERTIES_METHOD "Get"
#define DBUS_SSSD_PATH "/org/freedesktop/sssd/infopipe"
#define DBUS_SSSD_PATH_USERS "/org/freedesktop/sssd/infopipe/Users"
#define DBUS_SSSD_INTERFACE "org.freedesktop.sssd.infopipe"
#define DBUS_SSSD_INTERFACE_USERS "org.freedesktop.sssd.infopipe.Users"
#define DBUS_SSSD_INTERFACE_USER "org.freedesktop.sssd.infopipe.Users.User"

#define DBUS_SSSD_USER_ID "name"
#define DBUS_SSSD_GET_USER_GROUPS_METHOD "GetUserGroups"
#define DBUS_SSSD_GET_USER_ATTR_METHOD "GetUserAttr"

#define SEPARATOR_DEFAULT ":"

#define OUTPUT_VARIABLES 1
#define OUTPUT_HEADERS 2
#define OUTPUT_BASE64 4

#define IS_GROUP 0
#define IS_ATTRIBUTE 1

#define DIVIDED 0
#define TOGETHER 1

typedef struct {
    ngx_str_t key;
    ngx_array_t *values;
} property_info_t;

typedef struct {
    ngx_flag_t enabled;
    ngx_int_t output_to;
    ngx_str_t output_name_groups;
    ngx_str_t output_separator_groups;
    ngx_str_t output_name_group;
    ngx_array_t *output_name_attributes;
    ngx_array_t *output_name_attribute;
    ngx_str_t output_separator_attributes;
} ngx_http_sssd_info_loc_conf_t;

static void * ngx_http_sssd_info_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sssd_info_loc_conf_t *conf;
    conf = ngx_palloc(cf->pool, sizeof(ngx_http_sssd_info_loc_conf_t));
    if(conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enabled = NGX_CONF_UNSET;
    return conf;
}

static char * ngx_http_sssd_info_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_sssd_info_loc_conf_t *prev = parent;
    ngx_http_sssd_info_loc_conf_t *conf = child;

    ngx_conf_merge_off_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_str_value(conf->output_name_groups,
        prev->output_name_groups, "");
    ngx_conf_merge_str_value(conf->output_separator_groups,
        prev->output_separator_groups, SEPARATOR_DEFAULT);
    ngx_conf_merge_str_value(conf->output_name_group,
        prev->output_name_group, "");
    ngx_conf_merge_str_value(conf->output_separator_attributes,
        prev->output_separator_attributes, SEPARATOR_DEFAULT);

    if(conf->output_name_attributes == NULL) {
        if(prev->output_name_attributes != NULL) {
            conf->output_name_attributes = prev->output_name_attributes;
        } else {
            conf->output_name_attributes = NULL;
        }
    }
    if(conf->output_name_attribute == NULL) {
        if(prev->output_name_attribute != NULL) {
            conf->output_name_attribute = prev->output_name_attribute;
        } else {
            conf->output_name_attribute = NULL;
        }
    }

    return NGX_CONF_OK;
}

static char * ngx_http_sssd_info_set_output(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t *outputs = cf->args->elts;
    ngx_http_sssd_info_loc_conf_t *config = conf;
    ngx_int_t *output_pointer = (ngx_int_t *)(config + cmd->offset);

    u_int i;
    *output_pointer = 0;
    for(i = 0; i < cf->args->nelts; i++) {
        if(!ngx_strcasecmp(outputs[i].data, (u_char *)"base64")) {
            *output_pointer |= OUTPUT_BASE64;
        }
        if(!ngx_strcasecmp(outputs[i].data, (u_char *)"headers")) {
            *output_pointer |= OUTPUT_HEADERS;
        }
        if(!ngx_strcasecmp(outputs[i].data, (u_char *)"variables")) {
            *output_pointer |= OUTPUT_VARIABLES;
        }
    }

    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_sssd_info_commands[] = {
    { ngx_string("sssd_info"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sssd_info_loc_conf_t, enabled),
      NULL },
    { ngx_string("sssd_info_output_to"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123,
      ngx_http_sssd_info_set_output,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sssd_info_loc_conf_t, output_to),
      NULL },
    { ngx_string("sssd_info_groups"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sssd_info_loc_conf_t, output_name_groups),
      NULL },
    { ngx_string("sssd_info_group"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sssd_info_loc_conf_t, output_name_group),
      NULL },
    { ngx_string("sssd_info_group_separator"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sssd_info_loc_conf_t, output_separator_groups),
      NULL },
    { ngx_string("sssd_info_attributes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sssd_info_loc_conf_t, output_name_attributes),
      NULL },
    { ngx_string("sssd_info_attribute"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sssd_info_loc_conf_t, output_name_attribute),
      NULL },
    { ngx_string("sssd_info_attribute_separator"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sssd_info_loc_conf_t, output_separator_attributes),
      NULL },
      ngx_null_command
};

static ngx_int_t ngx_http_sssd_info_init(ngx_conf_t *cf);

static ngx_http_module_t ngx_http_sssd_info_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_sssd_info_init,                /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_http_sssd_info_create_loc_conf,     /* create location configuration */
    ngx_http_sssd_info_merge_loc_conf       /* merge location configuration */
};

ngx_module_t ngx_http_sssd_info_module = {
    NGX_MODULE_V1,
    &ngx_http_sssd_info_module_ctx,         /* module context */
    ngx_http_sssd_info_commands,            /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit precess */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

DBusMessage * sssd_dbus_message(ngx_http_request_t *r,
    DBusConnection *connection, DBusError *error, ngx_int_t timeout,
    const char * method, ngx_array_t *names)
{
    DBusMessage *message = dbus_message_new_method_call(DBUS_SSSD_DESTINATION,
        DBUS_SSSD_PATH, DBUS_SSSD_INTERFACE, method);
    if(!message) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: Not enough memory.");
        return NULL;
    }

    dbus_message_set_auto_start(message, TRUE);
    u_char *user = r->headers_in.user.data;
    if(names != NULL) {
        u_char **args = ngx_pcalloc(r->pool, names->nelts * sizeof(u_char *));
        if(args == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Not enough memory.");
            return NULL;
        }

        u_int i;
        ngx_keyval_t *namevals = names->elts;
        for(i = 0; i < names->nelts; i++) {
            args[i] = namevals[i].key.data;
        }

        dbus_message_append_args(message, DBUS_TYPE_STRING, &user,
            DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &args, names->nelts,
            DBUS_TYPE_INVALID);
    } else {
        dbus_message_append_args(message, DBUS_TYPE_STRING, &user,
            DBUS_TYPE_INVALID);
    }

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(connection,
        message, timeout, error);
    dbus_message_unref(message);
    ngx_int_t reply_type = DBUS_MESSAGE_TYPE_ERROR;
    if(!dbus_error_is_set(error)) {
        reply_type = dbus_message_get_type(reply);
        if(reply_type == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
            return reply;
        }
    }

    if(dbus_error_is_set(error)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: Dbus error with method %s: %s: %s.",
            method, error->name, error->message);
    } else if(reply_type == DBUS_MESSAGE_TYPE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: Dbus error with method %s: %s.",
            method, dbus_message_get_error_name(reply));
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: Unexpected reply type %d while calling %s method.",
            reply_type, method);
    }
    if(reply) {
        dbus_message_unref(reply);
    }
    return NULL;
}

static property_info_t * base64_encode_values(ngx_http_request_t *r,
    property_info_t *info)
{
    u_int i;
    property_info_t *encoded = ngx_pnalloc(r->pool, sizeof(property_info_t));
    encoded->key = info->key;
    encoded->values = ngx_array_create(r->pool, info->values->nelts,
        sizeof(ngx_str_t));
    ngx_str_t *values = info->values->elts;

    for(i = 0; i < info->values->nelts; i++) {
        ngx_str_t *encoded_elem = ngx_array_push(encoded->values);
        ngx_str_t tmp;
        tmp.len = ngx_base64_encoded_length(values[i].len);
        tmp.data = ngx_palloc(r->pool, tmp.len * sizeof(char));
        if(tmp.data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Not enough memory.");
            return NULL;
        }

        ngx_encode_base64(&tmp, &values[i]);
        *encoded_elem = tmp;
    }

    return encoded;
}

static ngx_str_t * copy_out_properties(ngx_http_request_t *r,
    property_info_t *info, ngx_str_t *separator)
{
    u_int i = 0;
    ngx_str_t *value = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
    value->len = 0;
    value->data = (u_char *)"";
    char *tmp;
    ngx_str_t *values = info->values->elts;

    while(i < info->values->nelts) {
        tmp = ngx_pnalloc(r->pool, value->len + 1);
        if(tmp == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Not enough memory.");
            return NULL;
        }
        snprintf(tmp, value->len + 1, "%s", (char *)value->data);

        value->len = value->len + values[i].len;
        value->data = ngx_pnalloc(r->pool, value->len);
        if(value->data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Not enough memory.");
            return NULL;
        }
        snprintf((char *)value->data, value->len + 1, "%s%s",
            tmp, (char *)values[i].data);
        i++;
        if(i < info->values->nelts) {
            tmp = ngx_pnalloc(r->pool,
                value->len + strlen((char *)separator->data) + 1);
            if(tmp == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_sssd_info: Not enough memory.");
                return NULL;
            }

            snprintf(tmp, value->len + strlen((char *)separator->data) + 1, 
                "%s%s", (char *)value->data, (char *)separator->data);
            ngx_str_set(value, tmp);
            value->len = strlen(tmp);
        }
    }

    return value;
}

static ngx_int_t output_variable(ngx_http_request_t *r, property_info_t *info,
    ngx_str_t *separator)
{
    return NGX_OK;
}

static ngx_int_t output_variables(ngx_http_request_t *r, property_info_t *info)
{
    return NGX_OK;
}

ngx_table_elt_t * create_header(ngx_http_request_t *r, ngx_str_t *key)
{
    ngx_table_elt_t *header = ngx_list_push(&r->headers_in.headers);
    if(header == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: Not enough memory.");
        return NULL;
    }

    header->key.len = key->len;
    header->key.data = key->data;

    header->lowcase_key = ngx_pnalloc(r->pool, header->key.len);
    if(header->lowcase_key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: Not enough memory.");
        return NULL;
    }
    ngx_strlow(header->lowcase_key, header->key.data, header->key.len);
    header->hash = ngx_hash_key(header->lowcase_key,
        strlen((char *)header->lowcase_key));

    return header;
}

static ngx_int_t output_header(ngx_http_request_t *r, property_info_t *info,
    ngx_str_t *separator)
{
    ngx_table_elt_t *header = create_header(r, &info->key);
    if(header == NULL) {
        return NGX_ERROR;
    }

    ngx_str_t *value = copy_out_properties(r, info, separator);
    if(value == NULL) {
        return NGX_ERROR;
    }

    header->value = *value;
    return NGX_OK;
}

static ngx_int_t output_headers(ngx_http_request_t *r, property_info_t *info)
{
    u_int i, len;
    ngx_str_t name;
    len = info->key.len + sizeof(ngx_int_t) + 2;
    ngx_str_t *values = info->values->elts;

    for(i = 0; i < info->values->nelts; i++) {
        name.data = ngx_pnalloc(r->pool, len + 1);
        if(name.data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Not enough memory.");
            return NGX_ERROR;
        }

        snprintf((char *)name.data, len + 1, "%s%s%d",
            (char *)info->key.data, "-", i + 1);
        name.len = strlen((char *)name.data);

        ngx_table_elt_t *header = create_header(r, &name);
        if(header == NULL) {
            return NGX_ERROR;
        }

        header->value = values[i];
    }

    name.data = ngx_pnalloc(r->pool, len + 1);
    snprintf((char *)name.data, len + 1, "%s%s", (char *)info->key.data, "-N");
    name.len = strlen((char *)name.data);
    ngx_table_elt_t *count = create_header(r, &name);
    if(count == NULL) {
        return NGX_ERROR;
    }

    count->value.data = ngx_pnalloc(r->pool, sizeof(ngx_int_t) + 1);
    if(count->value.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: Not enough memory.");
        return NGX_ERROR;
    }
    snprintf((char *)count->value.data, sizeof(ngx_int_t) + 1, "%d", i);
    count->value.len = strlen((char *)count->value.data);

    return NGX_OK;
}

static void switch_output(ngx_http_request_t *r, property_info_t *info,
    ngx_http_sssd_info_loc_conf_t *conf, ngx_int_t type, ngx_int_t together)
{
    if(info == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: No information to output");
        return;
    }
    ngx_int_t rc = NGX_OK;

    if(conf->output_to & OUTPUT_BASE64) {
        info = base64_encode_values(r, info);
    }
    if(info == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: Not enough memory, data will not be outputted");
        return;
    }

    if(conf->output_to & OUTPUT_VARIABLES) {
        if(together) {
            if(type == IS_GROUP) {
                rc = output_variable(r, info, &conf->output_separator_groups);
             } else {
                rc = output_variable(r, info,
                    &conf->output_separator_attributes);
             }
        } else {
            rc = output_variables(r, info);
        }
    }

    if(rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: An error occured, outputted data may be incorrect");
    }

    if(conf->output_to & OUTPUT_HEADERS) {
        if(together) {
            if(type == IS_GROUP) {
                rc = output_header(r, info, &conf->output_separator_groups);
            } else {
                rc = output_header(r, info, &conf->output_separator_attributes);
            }
        } else {
            rc = output_headers(r, info);
        }
    }

    if(rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: An error occured, outputted data may be incorrect");
    }
}

static ngx_str_t * find_output_name(ngx_array_t *keyvals, char *attr_name)
{
    ngx_keyval_t *keyval_elts = keyvals->elts;

    u_int i;
    for(i = 0; i < keyvals->nelts; i++) {
        if(!(ngx_strcmp(attr_name, keyval_elts[i].key.data))) {
            return &keyval_elts[i].value;
        }
    }

    return NULL;
}

static ngx_array_t * get_attribute_values(ngx_http_request_t *r,
    DBusMessage *reply, ngx_array_t *attribute_names)
{
    ngx_array_t *values = ngx_array_create(r->pool, attribute_names->nelts,
        sizeof(property_info_t));
    if(values == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: Not enough memory.");
        return NULL;
    }

    DBusMessageIter iter;
    dbus_message_iter_init(reply, &iter);
    ngx_int_t type = dbus_message_iter_get_arg_type(&iter);
    if(type != DBUS_TYPE_ARRAY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: Unexpected dbus type %d.", type);
        return NULL;
    }
    dbus_message_iter_recurse(&iter, &iter);
    do {
        type = dbus_message_iter_get_arg_type(&iter);
        if(type != DBUS_TYPE_DICT_ENTRY) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Unexpected dbus type %d.", type);
            return NULL;
        }

        DBusMessageIter dictiter;
        dbus_message_iter_recurse(&iter, &dictiter);
        char *attr_name;
        dbus_message_iter_get_basic(&dictiter, &attr_name);

        ngx_str_t *output_name = find_output_name(attribute_names, attr_name);
        if(output_name == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Unexpected attribute %s returned.", attr_name);
            continue;
        }
        if(!dbus_message_iter_next(&dictiter)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Empty value to attribute %s returned.",
                attr_name);
            continue;
        }
        type = dbus_message_iter_get_arg_type(&dictiter);
        if(type != DBUS_TYPE_VARIANT) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Unexpected dbus type %d.", type);
            continue;
        }
        dbus_message_iter_recurse(&dictiter, &dictiter);
        type = dbus_message_iter_get_arg_type(&dictiter);
        if(type != DBUS_TYPE_ARRAY) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Unexpected dbus type %d.", type);
            continue;
        }
        dbus_message_iter_recurse(&dictiter, &dictiter);
        property_info_t *value = ngx_array_push(values);
        value->key = *output_name;
        value->values = ngx_array_create(r->pool, 1, sizeof(ngx_str_t));
        if(value->values == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Not enough memory.");
            return NULL;
        }

        do {
            char *data;
            dbus_message_iter_get_basic(&dictiter, &data);
            ngx_str_t *tmp = ngx_array_push(value->values);
            ngx_str_set(tmp, data);
            tmp->len = strlen((char *)tmp->data);
        } while(dbus_message_iter_next(&dictiter));

    } while(dbus_message_iter_next(&iter));

    return values;
}

static ngx_int_t ngx_http_sssd_info_handler(ngx_http_request_t *r)
{
    ngx_http_sssd_info_loc_conf_t *loc_conf =
        ngx_http_get_module_loc_conf(r, ngx_http_sssd_info_module);
    if(!loc_conf->enabled) {
        return NGX_DECLINED;
    }

    if(!r->headers_in.user.len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_sssd_info: No authenticated user to retrive information for");
        return NGX_DECLINED;
    }

    if(!loc_conf->output_to) {
        loc_conf->output_to = OUTPUT_HEADERS | OUTPUT_VARIABLES;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_sssd_info: using default value for ngx_sssd_output_to");
    }

    DBusError error;
    DBusConnection *connection;
    DBusMessage *reply = NULL;
    u_int i;

    if(loc_conf->output_name_groups.len || loc_conf->output_name_group.len
        || loc_conf->output_name_attributes != NULL
        || loc_conf->output_name_attribute != NULL) {
        dbus_error_init(&error);
        connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
        if(!connection) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_sssd_info: Error while connecting to system dbus: %s",
                error.message);
            dbus_error_free(&error);
            return NGX_DECLINED;
        }

        dbus_connection_set_exit_on_disconnect(connection, FALSE);
        if(loc_conf->output_name_groups.len
            || loc_conf->output_name_group.len) {
            reply = sssd_dbus_message(r, connection, &error,
                DBUS_SSSD_TIMEOUT, DBUS_SSSD_GET_USER_GROUPS_METHOD, NULL);

            ngx_uint_t count = 0;
            char **ptr;
            if(reply && dbus_message_get_args(reply, &error, DBUS_TYPE_ARRAY,
                DBUS_TYPE_STRING, &ptr, &count, DBUS_TYPE_INVALID)) {
                property_info_t *info =
                    ngx_pnalloc(r->pool, sizeof(property_info_t));
                if(info == NULL) {
                    goto fail;
                }
                info->values =
                    ngx_array_create(r->pool, count, sizeof(ngx_str_t));
                if(info->values == NULL) {
                    goto fail;
                }

                for(i = 0; i < count; i++) {
                    ngx_str_t *tmp = ngx_array_push(info->values);
                    ngx_str_set(tmp, ptr[i]);
                    tmp->len = strlen(ptr[i]);
                }

                if(loc_conf->output_name_groups.len) {
                    info->key = loc_conf->output_name_groups;
                    switch_output(r, info, loc_conf, IS_GROUP, TOGETHER);
                }
                if(loc_conf->output_name_group.len) {
                    info->key = loc_conf->output_name_group;
                    switch_output(r, info, loc_conf, IS_GROUP, DIVIDED);
                }
            }

            if(reply) {
                dbus_message_unref(reply);
            }
            if(dbus_error_is_set(&error)) {
                dbus_error_free(&error);
            }
        }

        if(loc_conf->output_name_attributes) {
            DBusMessage *reply = sssd_dbus_message(r, connection, &error,
                DBUS_SSSD_TIMEOUT, DBUS_SSSD_GET_USER_ATTR_METHOD,
                loc_conf->output_name_attributes);
            if(reply) {
                ngx_array_t *values = get_attribute_values(r, reply,
                    loc_conf->output_name_attributes);
                if(values == NULL) {
                    goto fail;
                }
                property_info_t *attr_vals = values->elts;

                for(i = 0; i < values->nelts; i++) {
                    switch_output(r, &attr_vals[i], loc_conf, IS_ATTRIBUTE,
                        TOGETHER);
                }

                dbus_message_unref(reply);
                if(dbus_error_is_set(&error)) {
                    dbus_error_free(&error);
                }
            }
        }

        if(loc_conf->output_name_attribute) {
            DBusMessage *reply = sssd_dbus_message(r, connection, &error,
                DBUS_SSSD_TIMEOUT, DBUS_SSSD_GET_USER_ATTR_METHOD,
                loc_conf->output_name_attribute);
            if(reply) {
                ngx_array_t *values = get_attribute_values(r, reply,
                    loc_conf->output_name_attribute);
                if(values == NULL) {
                    goto fail;
                }
                property_info_t *attr_vals = values->elts;

                for(i = 0; i < values->nelts; i++) {
                    switch_output(r, &attr_vals[i], loc_conf, IS_ATTRIBUTE,
                        DIVIDED);
                }

                dbus_message_unref(reply);
                if(dbus_error_is_set(&error)) {
                    dbus_error_free(&error);
                }
            }
        }

        dbus_connection_unref(connection);
    }

    return NGX_OK;

fail:
    if(reply) {
        dbus_message_unref(reply);
    }
    if(dbus_error_is_set(&error)) {
        dbus_error_free(&error);
    }
    dbus_connection_unref(connection);

    return NGX_DECLINED;
}

static ngx_int_t ngx_http_sssd_info_init(ngx_conf_t *conf)
{
    ngx_http_handler_pt *handler;
    ngx_http_core_main_conf_t *main_conf;

    main_conf = ngx_http_conf_get_module_main_conf(conf, ngx_http_core_module);
    handler =
        ngx_array_push(&main_conf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if(handler == NULL) {
        return NGX_ERROR;
    }
    *handler = ngx_http_sssd_info_handler;

    //ngx_conf = conf;

    return NGX_OK;
}
