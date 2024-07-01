#include <math.h>
#include "avformat.h"
#include "libavutil/avassert.h"
#include "libavutil/avstring.h"
#include "libavutil/common.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "url.h"

#define ABR_NOT_SWITCH -1

#define ABR_THROUGHPUT_FIFO_LEN 20

enum ABRFormatType {
    ABR_TYPE_HLS,
    ABR_TYPE_DASH
};

typedef struct Variant {
    uint32_t bitrate;
    size_t index;
} variant;

typedef struct ABRContext {
    const AVClass *class;
    URLContext *hd;
    AVDictionary *abr_params;
    AVDictionary *abr_metadata;
    enum ABRFormatType format;
    uint8_t cur_var;
    uint8_t type;
    int8_t can_switch;
    size_t n_variants;
    variant *variants;

    size_t n_throughputs;
    float *throughputs;
} ABRContext;

// Get the average 
static float harmonic_mean(const float *arr, size_t num)
{
    float tmp = 0;

    if (!num) return 0;

    for (size_t i = 0; i < num; i++) {
        tmp += 1 / arr[i];
    }

    return num / tmp;
}

static int dash_param_parse(ABRContext *c, const AVDictionaryEntry *entry)
{
    AVDictionaryEntry *en;
    size_t index;
    char key_tmp[20];

    en = av_dict_get(c->abr_params, "cur_var", entry, AV_DICT_IGNORE_SUFFIX);
    if (en) {
        c->cur_var = strtol(en->value, NULL, 10);
    }
    en = av_dict_get(c->abr_params, "type", entry, AV_DICT_IGNORE_SUFFIX);
    if (en) {
        c->type = strtol(en->value, NULL, 10);
    }
    en = av_dict_get(c->abr_params, "can_switch", entry, AV_DICT_IGNORE_SUFFIX);
    if (en) {
        c->can_switch = strtol(en->value, NULL, 10);
    }
    en = av_dict_get(c->abr_params, "n_variants", entry, AV_DICT_IGNORE_SUFFIX);
    if (en) {
        c->n_variants = strtol(en->value, NULL, 10);
        c->variants = av_mallocz(sizeof(variant) * c->n_variants);
        if (!c->variants)
            return AVERROR(ENOMEM);
        index = 0;
        snprintf(key_tmp, sizeof(key_tmp), "variant_bitrate%ld", index);
        while ((en = av_dict_get(c->abr_params, key_tmp, entry, AV_DICT_IGNORE_SUFFIX))
               && index < c->n_variants) {
            c->variants[index].bitrate = strtol(en->value, NULL, 10);
            c->variants[index].index = index;
            index++;
            snprintf(key_tmp, sizeof(key_tmp), "variant_bitrate%ld", index);
        }
    }
    en = av_dict_get(c->abr_params, "n_throughputs", entry, AV_DICT_IGNORE_SUFFIX);
    if (en) {
        c->n_throughputs = strtol(en->value, NULL, 10);
        if (!c->n_throughputs)
            return 0;
        c->throughputs = av_malloc(sizeof(float) * c->n_throughputs);
        if (!c->throughputs)
            return AVERROR(ENOMEM);
        index = 0;
        snprintf(key_tmp, sizeof(key_tmp), "throughputs%ld", index);
        while ((en = av_dict_get(c->abr_params, key_tmp, entry, AV_DICT_IGNORE_SUFFIX))
               && index < c->n_throughputs) {
            c->throughputs[index++] = strtol(en->value, NULL, 10);
            snprintf(key_tmp, sizeof(key_tmp), "throughputs%ld", index);
        }
    }

    return 0;
}

static int abr_param_parse(ABRContext *c, enum ABRFormatType type, const AVDictionaryEntry *en)
{
    int ret;
    if (type == ABR_TYPE_DASH) {
        ret = dash_param_parse(c, en);
    }
    return ret;
}

static int compare_vb(const void *a, const void *b)
{
    return FFDIFFSIGN((*(const variant *)b).bitrate, (*(const variant *)a).bitrate);
}

// ABR rule 1 : throughput
static int abr_throughput_rule(URLContext *h, float bw_estimate)
{
    int ret = ABR_NOT_SWITCH;
    ABRContext *c = h->priv_data;

    // 0.8 - 1.2 
    if (bw_estimate < c->variants[c->cur_var].bitrate / 1000 * 1.2f &&
        bw_estimate > c->variants[c->cur_var].bitrate / 1000 * 0.8f)
        return ABR_NOT_SWITCH;

    qsort(c->variants, c->n_variants, sizeof(variant), compare_vb);
    for (int i = 0; i < c->n_variants; i++) {
        if (bw_estimate > c->variants[i].bitrate / 1000) {
            ret =  c->variants[i].index;
            break;
        }
    }
    if (ret == ABR_NOT_SWITCH)
        ret = c->variants[c->n_variants - 1].index;
    else if (ret == c->cur_var)
        ret = ABR_NOT_SWITCH;

    av_log(h, AV_LOG_VERBOSE, "[switch] bwe=%.2fkbps, cur=%d, switch=%d\n", bw_estimate, c->cur_var, ret);
    return ret;
}

// ABR rule 2 
static int abr_custom_rule(URLContext *h) 
{
    int ret = ABR_NOT_SWITCH;
    return ret;
}

static int abr_open(URLContext *h, const char *uri, int flags, AVDictionary **options)
{
    const char *nested_url;
    int64_t start, end;
    float bw_estimation;
    int switch_request = ABR_NOT_SWITCH;
    int ret = 0;
    ABRContext *c = h->priv_data;
    AVDictionaryEntry *en = NULL;

    if (!av_strstart(uri, "ffabr:", &nested_url)) {
        av_log(h, AV_LOG_ERROR, "Unsupported url %s\n", uri);
        return AVERROR(EINVAL);
    }

    // DASH/HLS supported
    en = av_dict_get(c->abr_params, "format", en, AV_DICT_IGNORE_SUFFIX);
    if (en) {
        if (!av_strcasecmp(en->value, "hls")) {
            c->format = ABR_TYPE_HLS;
        } else if (!av_strcasecmp(en->value, "dash")) {
            c->format = ABR_TYPE_DASH;
        }
        av_log(h, AV_LOG_VERBOSE, "%s is using ABR\n", en->value);
    } else {
        return AVERROR(EINVAL);
    }

    if (ret = abr_param_parse(c, c->format, en) < 0) {
        av_log(h, AV_LOG_ERROR,"Error parsing abr params.\n");
        return ret;
    }

    start = av_gettime();
    if ((ret = ffurl_open_whitelist(&c->hd, nested_url, flags,
                                    &h->interrupt_callback, options,
                                    h->protocol_whitelist, h->protocol_blacklist, h)) < 0) {
        av_log(h, AV_LOG_ERROR, "Unable to open resource: %s\n", nested_url);
        return ret;
    }
    end = av_gettime();

    bw_estimation = harmonic_mean(c->throughputs, c->n_throughputs);

    if (c->can_switch == 1)
        switch_request = abr_throughput_rule(h, bw_estimation);

    av_dict_set_int(&c->abr_metadata, "download_time", (end - start), 0);
    av_dict_set_int(&c->abr_metadata, "switch_request", switch_request, 0);
    av_dict_set_int(&c->abr_metadata, "type", c->type, 0);

    return ret;
}

static int abr_read(URLContext *h, uint8_t *buf, int size)
{
    ABRContext *c = h->priv_data;

    return ffurl_read(c->hd, buf, size);
}

static int64_t abr_seek(URLContext *h, int64_t pos, int whence)
{
    ABRContext *c = h->priv_data;

    if (whence == AVSEEK_SIZE) {
        return ffurl_seek(c->hd, pos, AVSEEK_SIZE);
    } else {
        return AVERROR(errno);
    }
}

static int abr_close(URLContext *h)
{
    ABRContext *c = h->priv_data;
    int ret = 0;

    ffurl_closep(&c->hd);
    av_free(c->variants);
    av_free(c->throughputs);
    return ret;
}

#define OFFSET(x) offsetof(ABRContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
static const AVOption ffabr_options[] = {
    { "abr-params",  "Informations ABR needed, using a :-separated list of key=value parameters", OFFSET(abr_params), AV_OPT_TYPE_DICT, { 0 }, 0, 0, D },
    { "abr-metadata",  "Metadata return from abr, including switch signal and network bandwidth", OFFSET(abr_metadata), AV_OPT_TYPE_DICT, { 0 }, 0, 0, D },
    { NULL }
};

static const AVClass ffabr_class = {
    .class_name = "ffabr",
    .item_name  = av_default_item_name,
    .option     = ffabr_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_ffabr_protocol = {
    .name            = "ffabr",
    .url_open2       = abr_open,
    .url_read        = abr_read,
    .url_seek        = abr_seek,
    .url_close       = abr_close,
    .priv_data_size  = sizeof(ABRContext),
    .priv_data_class = &ffabr_class,
};