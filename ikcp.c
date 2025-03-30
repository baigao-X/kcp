//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#include "ikcp.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#define IKCP_FASTACK_CONSERVE

//=====================================================================
// KCP BASIC
//=====================================================================
const IUINT32 IKCP_RTO_NDL = 30;		// no delay min rto
const IUINT32 IKCP_RTO_MIN = 100;		// normal min rto
const IUINT32 IKCP_RTO_DEF = 200;
const IUINT32 IKCP_RTO_MAX = 60000;
const IUINT32 IKCP_CMD_PUSH = 81;		// cmd: push data
const IUINT32 IKCP_CMD_ACK  = 82;		// cmd: ack
const IUINT32 IKCP_CMD_WASK = 83;		// cmd: window probe (ask)
const IUINT32 IKCP_CMD_WINS = 84;		// cmd: window size (tell)
const IUINT32 IKCP_ASK_SEND = 1;		// need to send IKCP_CMD_WASK
const IUINT32 IKCP_ASK_TELL = 2;		// need to send IKCP_CMD_WINS
const IUINT32 IKCP_WND_SND = 32;
const IUINT32 IKCP_WND_RCV = 128;       // must >= max fragment size
const IUINT32 IKCP_MTU_DEF = 1400;
const IUINT32 IKCP_ACK_FAST	= 3;
const IUINT32 IKCP_INTERVAL	= 100;
const IUINT32 IKCP_OVERHEAD = 24;       //kcp 头数据
const IUINT32 IKCP_DEADLINK = 20;
const IUINT32 IKCP_THRESH_INIT = 2;
const IUINT32 IKCP_THRESH_MIN = 2;
const IUINT32 IKCP_PROBE_INIT = 7000;		// 7 secs to probe window size
const IUINT32 IKCP_PROBE_LIMIT = 120000;	// up to 120 secs to probe window
const IUINT32 IKCP_FASTACK_LIMIT = 5;		// max times to trigger fastack


//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------

/* encode 8 bits unsigned int */
static inline char *ikcp_encode8u(char *p, unsigned char c)
{
	*(unsigned char*)p++ = c;
	return p;
}

/* decode 8 bits unsigned int */
static inline const char *ikcp_decode8u(const char *p, unsigned char *c)
{
	*c = *(unsigned char*)p++;
	return p;
}

/* encode 16 bits unsigned int (lsb) */
static inline char *ikcp_encode16u(char *p, unsigned short w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (w & 255);
	*(unsigned char*)(p + 1) = (w >> 8);
#else
	memcpy(p, &w, 2);
#endif
	p += 2;
	return p;
}

/* decode 16 bits unsigned int (lsb) */
static inline const char *ikcp_decode16u(const char *p, unsigned short *w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*w = *(const unsigned char*)(p + 1);
	*w = *(const unsigned char*)(p + 0) + (*w << 8);
#else
	memcpy(w, p, 2);
#endif
	p += 2;
	return p;
}

/* encode 32 bits unsigned int (lsb) */
static inline char *ikcp_encode32u(char *p, IUINT32 l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (unsigned char)((l >>  0) & 0xff);
	*(unsigned char*)(p + 1) = (unsigned char)((l >>  8) & 0xff);
	*(unsigned char*)(p + 2) = (unsigned char)((l >> 16) & 0xff);
	*(unsigned char*)(p + 3) = (unsigned char)((l >> 24) & 0xff);
#else
	memcpy(p, &l, 4);
#endif
	p += 4;
	return p;
}

/* decode 32 bits unsigned int (lsb) */
static inline const char *ikcp_decode32u(const char *p, IUINT32 *l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*l = *(const unsigned char*)(p + 3);
	*l = *(const unsigned char*)(p + 2) + (*l << 8);
	*l = *(const unsigned char*)(p + 1) + (*l << 8);
	*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else 
	memcpy(l, p, 4);
#endif
	p += 4;
	return p;
}

static inline IUINT32 _imin_(IUINT32 a, IUINT32 b) {
	return a <= b ? a : b;
}

static inline IUINT32 _imax_(IUINT32 a, IUINT32 b) {
	return a >= b ? a : b;
}

static inline IUINT32 _ibound_(IUINT32 lower, IUINT32 middle, IUINT32 upper) 
{
	return _imin_(_imax_(lower, middle), upper);
}

static inline long _itimediff(IUINT32 later, IUINT32 earlier) 
{
	return ((IINT32)(later - earlier));
}

//---------------------------------------------------------------------
// manage segment
//---------------------------------------------------------------------
typedef struct IKCPSEG IKCPSEG;

static void* (*ikcp_malloc_hook)(size_t) = NULL;
static void (*ikcp_free_hook)(void *) = NULL;

// internal malloc
static void* ikcp_malloc(size_t size) {
	if (ikcp_malloc_hook) 
		return ikcp_malloc_hook(size);
	return malloc(size);
}

// internal free
static void ikcp_free(void *ptr) {
	if (ikcp_free_hook) {
		ikcp_free_hook(ptr);
	}	else {
		free(ptr);
	}
}

// redefine allocator
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*))
{
	ikcp_malloc_hook = new_malloc;
	ikcp_free_hook = new_free;
}

// allocate a new kcp segment
static IKCPSEG* ikcp_segment_new(ikcpcb *kcp, int size)
{
	return (IKCPSEG*)ikcp_malloc(sizeof(IKCPSEG) + size);
}

// delete a segment
static void ikcp_segment_delete(ikcpcb *kcp, IKCPSEG *seg)
{
	ikcp_free(seg);
}

// write log
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...)
{
	char buffer[1024];
	va_list argptr;
	if ((mask & kcp->logmask) == 0 || kcp->writelog == 0) return;
	va_start(argptr, fmt);
	vsprintf(buffer, fmt, argptr);
	va_end(argptr);
	kcp->writelog(buffer, kcp, kcp->user);
}

// check log mask
static int ikcp_canlog(const ikcpcb *kcp, int mask)
{
	if ((mask & kcp->logmask) == 0 || kcp->writelog == NULL) return 0;
	return 1;
}

// output segment
static int ikcp_output(ikcpcb *kcp, const void *data, int size)
{
	assert(kcp);
	assert(kcp->output);
	if (ikcp_canlog(kcp, IKCP_LOG_OUTPUT)) {
		ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size);
	}
	if (size == 0) return 0;
	return kcp->output((const char*)data, size, kcp, kcp->user);
}

// output queue
void ikcp_qprint(const char *name, const struct IQUEUEHEAD *head)
{
#if 0
	const struct IQUEUEHEAD *p;
	printf("<%s>: [", name);
	for (p = head->next; p != head; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		printf("(%lu %d)", (unsigned long)seg->sn, (int)(seg->ts % 10000));
		if (p->next != head) printf(",");
	}
	printf("]\n");
#endif
}


//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
ikcpcb* ikcp_create(IUINT32 conv, void *user)
{
	ikcpcb *kcp = (ikcpcb*)ikcp_malloc(sizeof(struct IKCPCB));
	if (kcp == NULL) return NULL;
	kcp->conv = conv;
	kcp->user = user;
	kcp->snd_una = 0;
	kcp->snd_nxt = 0;
	kcp->rcv_nxt = 0;
	kcp->ts_recent = 0;
	kcp->ts_lastack = 0;
	kcp->ts_probe = 0;
	kcp->probe_wait = 0;
	kcp->snd_wnd = IKCP_WND_SND;
	kcp->rcv_wnd = IKCP_WND_RCV;
	kcp->rmt_wnd = IKCP_WND_RCV;
	kcp->cwnd = 0;
	kcp->incr = 0;
	kcp->probe = 0;
	kcp->mtu = IKCP_MTU_DEF;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	kcp->stream = 0;

	kcp->buffer = (char*)ikcp_malloc((kcp->mtu + IKCP_OVERHEAD) * 3);
	if (kcp->buffer == NULL) {
		ikcp_free(kcp);
		return NULL;
	}

	iqueue_init(&kcp->snd_queue);
	iqueue_init(&kcp->rcv_queue);
	iqueue_init(&kcp->snd_buf);
	iqueue_init(&kcp->rcv_buf);
	kcp->nrcv_buf = 0;
	kcp->nsnd_buf = 0;
	kcp->nrcv_que = 0;
	kcp->nsnd_que = 0;
	kcp->state = 0;
	kcp->acklist = NULL;
	kcp->ackblock = 0;
	kcp->ackcount = 0;
	kcp->rx_srtt = 0;
	kcp->rx_rttval = 0;
	kcp->rx_rto = IKCP_RTO_DEF;
	kcp->rx_minrto = IKCP_RTO_MIN;
	kcp->current = 0;
	kcp->interval = IKCP_INTERVAL;
	kcp->ts_flush = IKCP_INTERVAL;
	kcp->nodelay = 0;
	kcp->updated = 0;
	kcp->logmask = 0;
	kcp->ssthresh = IKCP_THRESH_INIT;
	kcp->fastresend = 0;
	kcp->fastlimit = IKCP_FASTACK_LIMIT;
	kcp->nocwnd = 0;
	kcp->xmit = 0;
	kcp->dead_link = IKCP_DEADLINK;
	kcp->output = NULL;
	kcp->writelog = NULL;

	return kcp;
}


//---------------------------------------------------------------------
// release a new kcpcb
//---------------------------------------------------------------------
void ikcp_release(ikcpcb *kcp)
{
	assert(kcp);
	if (kcp) {
		IKCPSEG *seg;
		while (!iqueue_is_empty(&kcp->snd_buf)) {
			seg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_buf)) {
			seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->snd_queue)) {
			seg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_queue)) {
			seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		if (kcp->buffer) {
			ikcp_free(kcp->buffer);
		}
		if (kcp->acklist) {
			ikcp_free(kcp->acklist);
		}

		kcp->nrcv_buf = 0;
		kcp->nsnd_buf = 0;
		kcp->nrcv_que = 0;
		kcp->nsnd_que = 0;
		kcp->ackcount = 0;
		kcp->buffer = NULL;
		kcp->acklist = NULL;
		ikcp_free(kcp);
	}
}


//---------------------------------------------------------------------
// set output callback, which will be invoked by kcp
//---------------------------------------------------------------------
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len,
	ikcpcb *kcp, void *user))
{
	kcp->output = output;
}


//---------------------------------------------------------------------
// user/upper level recv: returns size, returns below zero for EAGAIN
//---------------------------------------------------------------------
/**
 * 从KCP连接接收数据。
 * 
 * 该函数尝试从KCP连接接收数据，必要时会合并分片的数据包。
 * 它还会根据当前接收缓冲区的状态更新接收窗口并处理快速恢复。
 * 
 * 将发送队列中的数据分片合并，转移至用户区buffer
 * 
 * @param kcp 指向KCP连接结构的指针。不能为NULL。
 * @param buffer 存储接收到的数据的缓冲区。如果在窥视操作中设置为NULL，则不会将数据复制到缓冲区中。
 * @param len 缓冲区的长度。如果为负数，则表示窥视操作（不移除队列中的数据）。
 * @return 接收到的数据长度，或负错误码：
 *         - -1: 接收队列为空。
 *         - -2: 窥视大小失败（没有可用数据）。
 *         - -3: 缓冲区太小，无法容纳即将接收的数据。
 */
int ikcp_recv(ikcpcb *kcp, char *buffer, int len)
{
    struct IQUEUEHEAD *p;
    int ispeek = (len < 0) ? 1 : 0;  // 判断是否为窥视操作
    int peeksize;
    int recover = 0;
    IKCPSEG *seg;
    assert(kcp);  // 确保kcp指针不为NULL

    if (iqueue_is_empty(&kcp->rcv_queue))
        return -1;  // 接收队列为空

    if (len < 0)
        len = -len;  // 如果是窥视操作，取len的绝对值

    peeksize = ikcp_peeksize(kcp);  // 获取下一个数据包的大小

    if (peeksize < 0)
        return -2;  // 窥视大小失败

    if (peeksize > len)
        return -3;  // 缓冲区太小

    if (kcp->nrcv_que >= kcp->rcv_wnd)
        recover = 1;  // 需要快速恢复

    // 合并分片
    for (len = 0, p = kcp->rcv_queue.next; p != &kcp->rcv_queue; ) {
        int fragment;
        seg = iqueue_entry(p, IKCPSEG, node);
        p = p->next;

        if (buffer) {
            memcpy(buffer, seg->data, seg->len);
            buffer += seg->len;
        }

        len += seg->len;
        fragment = seg->frg;

        if (ikcp_canlog(kcp, IKCP_LOG_RECV)) {
            ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=%lu", (unsigned long)seg->sn);
        }

        if (ispeek == 0) {
            iqueue_del(&seg->node);
            ikcp_segment_delete(kcp, seg);
            kcp->nrcv_que--;
        }

        if (fragment == 0)
            break;
    }

    assert(len == peeksize);

    // 将可用数据从rcv_buf移动到rcv_queue
    while (!iqueue_is_empty(&kcp->rcv_buf)) {
        seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
        if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
            iqueue_del(&seg->node);
            kcp->nrcv_buf--;
            iqueue_add_tail(&seg->node, &kcp->rcv_queue);
            kcp->nrcv_que++;
            kcp->rcv_nxt++;
        } else {
            break;
        }
    }

    // 快速恢复
    if (kcp->nrcv_que < kcp->rcv_wnd && recover) {
        // 准备在ikcp_flush中发送IKCP_CMD_WINS
        // 告诉远程端我的窗口大小
        kcp->probe |= IKCP_ASK_TELL;
    }

    return len;
}


//---------------------------------------------------------------------
// peek data size
//---------------------------------------------------------------------
/**
 * 获取 KCP 协议中接收队列中一个数据包的大小(若数据包由多个分片组成，返回多个分片的大小总和)
 * 
 * @param kcp KCP 协议控制块指针，用于访问 KCP 协议的相关数据
 * @return 返回完整数据的大小如果返回 -1，则表示接收队列为空或者数据分片不完整
 */
int ikcp_peeksize(const ikcpcb *kcp)
{
    // 链表节点指针，用于遍历接收队列
    struct IQUEUEHEAD *p;
    // KCP 数据段指针，用于访问数据段的长度和分片信息
    IKCPSEG *seg;
    // 用于累加完整数据的长度
    int length = 0;

    // 确保 KCP 协议控制块指针非空
    assert(kcp);

    // 如果接收队列为空，则返回 -1 表示没有数据可接收
    if (iqueue_is_empty(&kcp->rcv_queue)) return -1;

    // 获取接收队列中第一个数据段
    seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
    // 如果第一个数据段是完整的（不分片），则直接返回该数据段的长度
    if (seg->frg == 0) return seg->len;

    // 如果数据分片数量不匹配，即接收的数据分片不完整，则返回 -1
    if (kcp->nrcv_que < seg->frg + 1) return -1;

    // 遍历接收队列，累加所有数据段的长度，直到遇到第一个完整的数据段
    for (p = kcp->rcv_queue.next; p != &kcp->rcv_queue; p = p->next) {
        seg = iqueue_entry(p, IKCPSEG, node);
        length += seg->len;
        // 如果遇到完整的数据段，则停止累加
        if (seg->frg == 0) break;
    }

    // 返回累加的完整数据的长度
    return length;
}


//---------------------------------------------------------------------
// user/upper level send, returns below zero for error
//---------------------------------------------------------------------

//将要发送的数据加入到发送队列snd_queue中
int ikcp_send(ikcpcb *kcp, const char *buffer, int len)
{
	IKCPSEG *seg;
	int count;  //表示当前的数据需要多少分片。一个分片最多mss大小
	int i;
	int sent = 0; //发送的数据量长度

	assert(kcp->mss > 0);
	if (len < 0) return -1;

	// append to previous segment in streaming mode (if possible)
	// 如果开启了流模式，尝试将数据合并到最后一个段
	if (kcp->stream != 0) {
		// 如果发送队列不为空，尝试将数据追加到最后一个段
		// 每个段最多mss大小
		if (!iqueue_is_empty(&kcp->snd_queue)) {
			IKCPSEG *old = iqueue_entry(kcp->snd_queue.prev, IKCPSEG, node);
			// 如果最后一个段的数据长度小于MSS，可以尝试合并
			if (old->len < kcp->mss) {
				int capacity = kcp->mss - old->len;
				int extend = (len < capacity)? len : capacity;
				seg = ikcp_segment_new(kcp, old->len + extend);
				assert(seg);
				if (seg == NULL) {
					return -2;
				}
				iqueue_add_tail(&seg->node, &kcp->snd_queue);
				
				memcpy(seg->data, old->data, old->len);
				if (buffer) {
					memcpy(seg->data + old->len, buffer, extend);
					buffer += extend;
				}
				seg->len = old->len + extend;
				seg->frg = 0;
				len -= extend;
				iqueue_del_init(&old->node);
				ikcp_segment_delete(kcp, old);
				sent = extend;
			}
		}
		// 如果数据已经全部合并，直接返回
		if (len <= 0) {
			return sent;
		}
	}

	if (len <= (int)kcp->mss) count = 1;
	else count = (len + kcp->mss - 1) / kcp->mss;

	// 分片数量不能超过最大限制
	if (count >= (int)IKCP_WND_RCV) {
		if (kcp->stream != 0 && sent > 0) 
			return sent;
		return -2;
	}

    // 如果分片数量为0，至少需要一个分片
	if (count == 0) count = 1;

	// fragment
	// 创建所有分片
	for (i = 0; i < count; i++) {
		int size = len > (int)kcp->mss ? (int)kcp->mss : len;
		seg = ikcp_segment_new(kcp, size);
		assert(seg);
		if (seg == NULL) {
			return -2;
		}
		if (buffer && len > 0) {
			memcpy(seg->data, buffer, size);
		}
		seg->len = size;
		seg->frg = (kcp->stream == 0)? (count - i - 1) : 0;
		iqueue_init(&seg->node);
		iqueue_add_tail(&seg->node, &kcp->snd_queue);
		kcp->nsnd_que++;
		if (buffer) {
			buffer += size;
		}
		len -= size;
		sent += size;
	}

	return sent;
}


//---------------------------------------------------------------------
// parse ack
//---------------------------------------------------------------------
/**
 * 更新ACK信息以调整重传时间
 * 
 * 根据当前的往返时间（rtt）更新ACK的重传时间参数这个函数主要用于维护TCP友好的拥塞控制算法
 * 它通过不断更新对端到端网络延迟的估计来优化数据包的重传机制
 * 
 * @param kcp KCP协议控制块指针，包含所有需要更新的状态信息
 * @param rtt 当前的往返时间，单位为毫秒
 */
static void ikcp_update_ack(ikcpcb *kcp, IINT32 rtt)
{
    IINT32 rto = 0;
    
    // 初始化往返时间平滑值和往返时间偏差值
    if (kcp->rx_srtt == 0) {
        kcp->rx_srtt = rtt;
        kcp->rx_rttval = rtt / 2;
    } else {
        // 计算当前rtt与平滑rtt的差值，并取绝对值
        long delta = rtt - kcp->rx_srtt;
        if (delta < 0) delta = -delta;
        
        // 更新往返时间偏差值和往返时间平滑值
		//RFC 6289 TCP rtt 和rtt方差计算公式：
		//RTTVAR(RTT方差) = 3/4 RTTVAR + 1/8 |new_rtt - SRTT|
		//SRTT(平滑后RTT) = 7/8 SRTT + 1/8 new_rtt
        kcp->rx_rttval = (3 * kcp->rx_rttval + delta) / 4; 
        kcp->rx_srtt = (7 * kcp->rx_srtt + rtt) / 8;
        if (kcp->rx_srtt < 1) kcp->rx_srtt = 1;
    }
    
    // 计算重传时间
	// 方差用于反应RTT与平均值的偏离程度,用于量化网络抖动，用于动态调整重传超时时间(RTO)
    rto = kcp->rx_srtt + _imax_(kcp->interval, 4 * kcp->rx_rttval);
    
    // 限制重传时间在最小和最大值之间
    kcp->rx_rto = _ibound_(kcp->rx_minrto, rto, IKCP_RTO_MAX);
}

//---------------------------------------------------------------------
// shrink the size of the sending buffer
//---------------------------------------------------------------------
/**
 * ikcp_shrink_buf函数的目的缩小发送缓冲区
 * 当发送缓冲区中的数据被确认接收后，更新发送未确认序号
 * 这有助于管理发送缓冲区，确保可靠传输
 */
static void ikcp_shrink_buf(ikcpcb *kcp)
{
    // p指向发送缓冲区中的第一个元素
    struct IQUEUEHEAD *p = kcp->snd_buf.next;
    // 如果发送缓冲区不为空
    if (p != &kcp->snd_buf) {
        // 获取第一个数据段的指针
        IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
        // 更新发送未确认序号为发送缓冲区中第一个段的序号
        kcp->snd_una = seg->sn;
    } else {
        // 如果发送缓冲区为空，更新发送未确认序号为发送下一个序号
        kcp->snd_una = kcp->snd_nxt;
    }
}

/**
 * 处理接收方确认的序列号
 * 当接收到对方的ACK时，通过此函数来更新发送方的缓冲区
 * 
 * @param kcp KCP协议控制块指针
 * @param sn 接收到的ACK序列号
 */
static void ikcp_parse_ack(ikcpcb *kcp, IUINT32 sn)
{
    struct IQUEUEHEAD *p, *next;

    // 检查ACK序列号是否在有效范围内
    if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
        return;

    // 遍历发送缓冲区，寻找匹配的序列号
    for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
        IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
        next = p->next;
        // 当找到匹配的序列号时，从缓冲区中删除对应的段
        if (sn == seg->sn) {
            iqueue_del(p);
            ikcp_segment_delete(kcp, seg);
            kcp->nsnd_buf--;
            break;
        }
        // 如果当前段的序列号已经大于ACK序列号，则无需继续查找
        if (_itimediff(sn, seg->sn) < 0) {
            break;
        }
    }
}

/**
 * ikcp_parse_una函数用于处理接收方已确认的数据包序列号
 * 该函数主要用于删除发送缓冲区中已经确认被接收的数据包
 * 
 * @param kcp ikcp connection struct pointer, 即IKCP连接结构体的指针
 * @param una 接收方已确认的数据包序列号
 */
static void ikcp_parse_una(ikcpcb *kcp, IUINT32 una)
{
    struct IQUEUEHEAD *p, *next;
    // 遍历发送缓冲区中的所有段
    for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
        IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
        next = p->next;
        // 如果确认号大于当前段的序列号，表示该段已被确认
        if (_itimediff(una, seg->sn) > 0) {
            iqueue_del(p); // 从发送缓冲区中删除该段
            ikcp_segment_delete(kcp, seg); // 释放该段的内存
            kcp->nsnd_buf--; // 减少发送缓冲区中的段数
        } else {
            break; // 如果确认号不大于当前段的序列号，停止遍历
        }
    }
}

/**
 * 快速确认解析函数
 * 
 * 该函数用于处理快速确认（fastack）机制，以优化数据包的重传和拥塞控制
 * 它通过更新发送缓冲区中数据包的快速确认计数，帮助KCP协议更好地理解网络状况
 * 
 * @param kcp KCP连接对象指针，代表一个KCP连接
 * @param sn 接收到的数据包的序列号，用于确认数据包
 * @param ts 接收到的数据包的时间戳，用于计算网络延迟和拥塞情况
 */
static void ikcp_parse_fastack(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
    struct IQUEUEHEAD *p, *next;

    // 检查序列号是否在可确认的范围内，如果不是，则直接返回
    if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
        return;

    // 遍历发送缓冲区中的所有数据包，更新快速确认计数
    for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
        IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
        next = p->next;
        // 如果当前数据包的序列号小于要确认的序列号，继续检查下一个数据包
        if (_itimediff(sn, seg->sn) < 0) {
            break;
        }
        // 如果当前数据包的序列号与要确认的序列号不匹配，根据编译选项更新快速确认计数
        else if (sn != seg->sn) {
            #ifndef IKCP_FASTACK_CONSERVE
                seg->fastack++;
            #else
                // 在保守快速确认模式下，只有当接收到的数据包时间戳晚于或等于数据包发送时间戳时，才增加快速确认计数
                if (_itimediff(ts, seg->ts) >= 0)
                    seg->fastack++;
            #endif
        }
    }
}

//---------------------------------------------------------------------
// ack append
//---------------------------------------------------------------------
/**
 * 向KCP协议的ACK队列中添加一个ACK信息
 * 
 * @param kcp KCP协议控制块指针
 * @param sn 接收到的ACK的序列号
 * @param ts 接收到的ACK的时间戳
 */
static void ikcp_ack_push(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
    // 计算新的ACK队列大小
    IUINT32 newsize = kcp->ackcount + 1;
    IUINT32 *ptr;

    // 如果新的ACK队列大小超过了当前的ACK块大小，则需要扩容
    if (newsize > kcp->ackblock) {
        IUINT32 *acklist;
        IUINT32 newblock;

        // 计算新的ACK块大小，至少为8，并且每次翻倍，直到大于newsize
        for (newblock = 8; newblock < newsize; newblock <<= 1);
        // 分配新的ACK块内存，同时存储序列号和时间戳，所以大小乘以2
        acklist = (IUINT32*)ikcp_malloc(newblock * sizeof(IUINT32) * 2);

        // 如果内存分配失败，则终止程序
        if (acklist == NULL) {
            assert(acklist != NULL);
            abort();
        }

        // 如果原来的ACK队列不为空，则将原来的ACK信息复制到新的ACK块中
        if (kcp->acklist != NULL) {
            IUINT32 x;
            for (x = 0; x < kcp->ackcount; x++) {
                acklist[x * 2 + 0] = kcp->acklist[x * 2 + 0];
                acklist[x * 2 + 1] = kcp->acklist[x * 2 + 1];
            }
            // 释放原来的ACK块内存
            ikcp_free(kcp->acklist);
        }

        // 更新KCP协议控制块中的ACK队列指针和块大小
        kcp->acklist = acklist;
        kcp->ackblock = newblock;
    }

    // 在ACK队列中添加新的ACK信息
    ptr = &kcp->acklist[kcp->ackcount * 2];
    ptr[0] = sn;
    ptr[1] = ts;
    // 更新ACK队列中的ACK数量
    kcp->ackcount++;
}

static void ikcp_ack_get(const ikcpcb *kcp, int p, IUINT32 *sn, IUINT32 *ts)
{
	if (sn) sn[0] = kcp->acklist[p * 2 + 0];
	if (ts) ts[0] = kcp->acklist[p * 2 + 1];
}


//---------------------------------------------------------------------
// parse data
//--------------------------------------------------------------------
/**
 * 解析接收到的数据包并更新接收缓冲区rcv_nxt
 * 
 * @param kcp KCP协议控制块指针，用于存储协议状态和接收缓冲区信息
 * @param newseg 新接收到的数据包指针，包含序列号和数据
 * 
 * 此函数首先检查新数据包的序列号是否在接收窗口范围内如果不在范围内，则删除该数据包
 * 然后，函数遍历接收缓冲区，查找是否已经存在相同序列号的数据包如果存在，则标记为重复并删除该数据包
 * 如果数据包不重复，则将其添加到接收缓冲区中
 * 最后，函数将接收缓冲区中序列号连续且在接收窗口范围内的数据包移动到接收队列中
 */
void ikcp_parse_data(ikcpcb *kcp, IKCPSEG *newseg)
{
    struct IQUEUEHEAD *p, *prev;
    IUINT32 sn = newseg->sn;
    int repeat = 0;
    
    // 检查新数据包的序列号是否在接收窗口范围内
    if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) >= 0 ||
        _itimediff(sn, kcp->rcv_nxt) < 0) {
        ikcp_segment_delete(kcp, newseg);
        return;
    }

    // 遍历接收缓冲区，查找重复的序列号
    for (p = kcp->rcv_buf.prev; p != &kcp->rcv_buf; p = prev) {
        IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
        prev = p->prev;
        if (seg->sn == sn) {
            repeat = 1;
            break;
        }
        if (_itimediff(sn, seg->sn) > 0) {
            break;
        }
    }

    // 根据是否重复，决定是添加到接收缓冲区还是删除
    if (repeat == 0) {
        iqueue_init(&newseg->node);
        iqueue_add(&newseg->node, p);
        kcp->nrcv_buf++;
    } else {
        ikcp_segment_delete(kcp, newseg);
    }

#if 0
    ikcp_qprint("rcvbuf", &kcp->rcv_buf);
    printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

    // 将可用数据从接收缓冲区移动到接收队列
    while (! iqueue_is_empty(&kcp->rcv_buf)) {
        IKCPSEG *seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
        if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
            iqueue_del(&seg->node);
            kcp->nrcv_buf--;
            iqueue_add_tail(&seg->node, &kcp->rcv_queue);
            kcp->nrcv_que++;
            kcp->rcv_nxt++;
        } else {
            break;
        }
    }

#if 0
    ikcp_qprint("queue", &kcp->rcv_queue);
    printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

#if 1
    // printf("snd(buf=%d, queue=%d)\n", kcp->nsnd_buf, kcp->nsnd_que);
    // printf("rcv(buf=%d, queue=%d)\n", kcp->nrcv_buf, kcp->nrcv_que);
#endif
}-


//---------------------------------------------------------------------
// input data
//---------------------------------------------------------------------
/**
 * ikcp_input函数负责处理来自网络的数据包，更新KCP协议的状态
 * 该函数解码接收到的数据，根据数据包的类型执行相应的操作，如更新ACK、接收数据等
 * //收到任何包：
 *  1. 更新对端的窗口报文中的wnd 到 rmt_wnd
 * 	2.根据确认号(una)调整待确认序号(snd_und),该序号之前的所有数据都认为已经确认,移除发送缓存(snd_buf)中的已确认数据。
 * //收到快速ack包： 
 * 	1.将确认号(ack包中的sn)的那个包标记为已经确认，并移除发送缓存(snd_buf)中的已确认数据
 *  2.将收到的快速ack包中最大序列号(sn)和最新时间戳(ts) 用于更新fastack(该值用于控制是否进行快速重传)
 * //收到win探测包,标志发送win包(如果正好要发其他数据，不会单独发送win包)
 * //收到win包，更新rmt_win数据
 * //收到push的data：
 *  1.数据段加入到接收缓冲区(rcv_buf)
 *  2.将其中的序号连续部分移动到接收队列(rcv_queue)中，并更新rcv_nxt
 *  3.更新待发送的acklist
 * 	.
 *  如果有新数据更新，且本地拥塞窗口小于对端拥塞窗口，则调整拥塞窗口(cwnd, incr)
 * 
 * 
 * @param kcp 指向KCP协议控制块的指针，用于存储协议状态
 * @param data 指向接收到的数据包的指针
 * @param size 数据包的大小
 * @return 返回0表示成功，非0表示出错
 */
int ikcp_input(ikcpcb *kcp, const char *data, long size)
{
    IUINT32 prev_una = kcp->snd_una; // 记录当前未确认包的序号
    IUINT32 maxack = 0;              // 最大确认号
    IUINT32 latest_ts = 0;          // 最近的时间戳
    int flag = 0;                    // 标记是否收到快速ACK(即单独的ACK确认)

    // 日志记录输入数据大小
    if (ikcp_canlog(kcp, IKCP_LOG_INPUT)) {
        ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", (int)size);
    }

    // 检查输入数据的有效性
    if (data == NULL || (int)size < (int)IKCP_OVERHEAD) return -1;

    // 循环解析输入数据
    while (1) {
        IUINT32 conv;  // 会话ID
        IUINT8  frg;   // 分片序号(倒序)
        IUINT8  cmd;   // 命令
        IUINT16 wnd;   // 剩余接收窗口大小
        IUINT32 ts;    // 时间戳
        IUINT32 sn;    // 序列号
        IUINT32 una;   // 确认号
        IUINT32 len;   // 数据长度
        IKCPSEG *seg;

        // 检查剩余数据是否足够解析一个包头
        if (size < (int)IKCP_OVERHEAD) break;

        // 解析包头字段
        data = ikcp_decode32u(data, &conv);
        if (conv != kcp->conv) return -1; // 检查会话ID是否匹配

        data = ikcp_decode8u(data, &cmd);
        data = ikcp_decode8u(data, &frg);
        data = ikcp_decode16u(data, &wnd);
        data = ikcp_decode32u(data, &ts);
        data = ikcp_decode32u(data, &sn);
        data = ikcp_decode32u(data, &una);
        data = ikcp_decode32u(data, &len);

        // 检查数据长度是否有效
        size -= IKCP_OVERHEAD;
        if ((long)size < (long)len || (int)len < 0) return -2;

        // 检查命令是否有效
        if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
            cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS) 
            return -3;

        // 更新远程窗口大小
        kcp->rmt_wnd = wnd;
        // 解析确认号
        ikcp_parse_una(kcp, una);
        // 收缩发送缓冲区
        ikcp_shrink_buf(kcp);

        // 处理ACK命令
        if (cmd == IKCP_CMD_ACK) {
            // 更新RTT,RTT方差,重传超时时间(RTO)
            if (_itimediff(kcp->current, ts) >= 0) {
                ikcp_update_ack(kcp, _itimediff(kcp->current, ts));
            }
            // 解析ACK
            ikcp_parse_ack(kcp, sn);
            // 收缩发送缓冲区
            ikcp_shrink_buf(kcp);
            // 记录最大ACK和时间戳
            if (flag == 0) {
                flag = 1;
                maxack = sn;
                latest_ts = ts;
            }	else {
                if (_itimediff(sn, maxack) > 0) {
                #ifndef IKCP_FASTACK_CONSERVE
                    maxack = sn;
                    latest_ts = ts;
                #else
                    if (_itimediff(ts, latest_ts) > 0) {
                        maxack = sn;
                        latest_ts = ts;
                    }
                #endif
                }
            }
            // 日志记录收到的ACK
            if (ikcp_canlog(kcp, IKCP_LOG_IN_ACK)) {
                ikcp_log(kcp, IKCP_LOG_IN_ACK, 
                    "input ack: sn=%lu rtt=%ld rto=%ld", (unsigned long)sn, 
                    (long)_itimediff(kcp->current, ts),
                    (long)kcp->rx_rto);
            }
        }
        // 处理PUSH命令
        else if (cmd == IKCP_CMD_PUSH) {
            // 日志记录收到的数据包
            if (ikcp_canlog(kcp, IKCP_LOG_IN_DATA)) {
                ikcp_log(kcp, IKCP_LOG_IN_DATA, 
                    "input psh: sn=%lu ts=%lu", (unsigned long)sn, (unsigned long)ts);
            }
            // 检查序列号是否在接收窗口内
            if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) < 0) {
                // 推送ACK
                ikcp_ack_push(kcp, sn, ts);
                // 如果序列号大于等于接收序号，解析数据包
                if (_itimediff(sn, kcp->rcv_nxt) >= 0) {
                    seg = ikcp_segment_new(kcp, len);
                    seg->conv = conv;
                    seg->cmd = cmd;
                    seg->frg = frg;
                    seg->wnd = wnd;
                    seg->ts = ts;
                    seg->sn = sn;
                    seg->una = una;
                    seg->len = len;

                    if (len > 0) {
                        memcpy(seg->data, data, len);
                    }

                    // 解析数据包
                    ikcp_parse_data(kcp, seg);
                }
            }
        }
        // 处理WASK命令
        else if (cmd == IKCP_CMD_WASK) {
            // 准备发送WINS命令
            kcp->probe |= IKCP_ASK_TELL;
            // 日志记录收到的WASK命令
            if (ikcp_canlog(kcp, IKCP_LOG_IN_PROBE)) {
                ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe");
            }
        }
        // 处理WINS命令
        else if (cmd == IKCP_CMD_WINS) {
            // 不做任何处理
            // 日志记录收到的WINS命令
            if (ikcp_canlog(kcp, IKCP_LOG_IN_WINS)) {
                ikcp_log(kcp, IKCP_LOG_IN_WINS,
                    "input wins: %lu", (unsigned long)(wnd));
            }
        }
        else {
            return -3;
        }

        // 移动数据指针和大小
        data += len;
        size -= len;
    }

    // 解析快速ACK
    if (flag != 0) {
        ikcp_parse_fastack(kcp, maxack, latest_ts);
    }

    // 如果未确认包序号有变化，调整拥塞窗口
    if (_itimediff(kcp->snd_una, prev_una) > 0) {
        // 当当前拥塞窗口小于远程窗口时，进行拥塞控制
        if (kcp->cwnd < kcp->rmt_wnd) {
            IUINT32 mss = kcp->mss;
            // 如果当前拥塞窗口小于阈值，使用线性增长方式
            if (kcp->cwnd < kcp->ssthresh) {
                kcp->cwnd++;
                kcp->incr += mss;
            } else {
                // 否则，使用拥塞避免算法进行非线性增长
                if (kcp->incr < mss) kcp->incr = mss;
                kcp->incr += (mss * mss) / kcp->incr + (mss / 16);
                // 当增长量足够大时，按增长量更新拥塞窗口
                if ((kcp->cwnd + 1) * mss <= kcp->incr) {
                    #if 1
                        kcp->cwnd = (kcp->incr + mss - 1) / ((mss > 0)? mss : 1);
                    #else
                        kcp->cwnd++;
                    #endif
                }
            }
            // 确保拥塞窗口不超过远程窗口大小
            if (kcp->cwnd > kcp->rmt_wnd) {
                kcp->cwnd = kcp->rmt_wnd;
                kcp->incr = kcp->rmt_wnd * mss;
            }
        }
    }
	
    return 0;
}


//---------------------------------------------------------------------
// ikcp_encode_seg
//---------------------------------------------------------------------
static char *ikcp_encode_seg(char *ptr, const IKCPSEG *seg)
{
	ptr = ikcp_encode32u(ptr, seg->conv);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->cmd);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->frg);
	ptr = ikcp_encode16u(ptr, (IUINT16)seg->wnd);
	ptr = ikcp_encode32u(ptr, seg->ts);
	ptr = ikcp_encode32u(ptr, seg->sn);
	ptr = ikcp_encode32u(ptr, seg->una);
	ptr = ikcp_encode32u(ptr, seg->len);
	return ptr;
}

static int ikcp_wnd_unused(const ikcpcb *kcp)
{
	if (kcp->nrcv_que < kcp->rcv_wnd) {
		return kcp->rcv_wnd - kcp->nrcv_que;
	}
	return 0;
}


//---------------------------------------------------------------------
// ikcp_flush
//---------------------------------------------------------------------

/**
 * ikcp_flush函数负责将KCP协议中的数据和控制信息发送到对端。
 * 它会处理ACK确认、窗口探测、数据段重传等操作，并根据网络状况调整拥塞窗口。
 * 
 * @param kcp 指向KCP协议控制块的指针，用于存储协议状态和发送缓冲区信息。
 * 
 * 该函数的主要功能包括：
 * 1. 发送ACK确认信息。
 * 2. 探测远程窗口大小（如果远程窗口为0）。
 * 3. 发送窗口探测命令（WASK/WINS）。
 * 4. 计算拥塞窗口并移动数据从发送队列到发送缓冲区。
 * 5. 处理数据段重传，包括快速重传和超时重传。
 * 6. 更新拥塞窗口和慢启动阈值。
 */
void ikcp_flush(ikcpcb *kcp)
{
    // 如果'ikcp_update'尚未被调用，直接返回
    if (kcp->updated == 0) return;

    // 初始化ACK段
    IKCPSEG seg;
    seg.conv = kcp->conv;
    seg.cmd = IKCP_CMD_ACK;
    seg.frg = 0;
    seg.wnd = ikcp_wnd_unused(kcp);
    seg.una = kcp->rcv_nxt;
    seg.len = 0;
    seg.sn = 0;
    seg.ts = 0;

    // 发送所有待处理的ACK确认信息
    int count = kcp->ackcount;
    for (int i = 0; i < count; i++) {
        char *ptr = buffer;
        int size = (int)(ptr - buffer);
        if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
            ikcp_output(kcp, buffer, size);
            ptr = buffer;
        }
        ikcp_ack_get(kcp, i, &seg.sn, &seg.ts);
        ptr = ikcp_encode_seg(ptr, &seg);
    }
    kcp->ackcount = 0;

    // 如果远程窗口大小为0，探测窗口大小
    if (kcp->rmt_wnd == 0) {
        if (kcp->probe_wait == 0) {
            kcp->probe_wait = IKCP_PROBE_INIT;
            kcp->ts_probe = kcp->current + kcp->probe_wait;
        } else {
			//如果超过窗口探测器，还没接收到对端的wnd大小，主动发送窗口探测大小包
            if (_itimediff(kcp->current, kcp->ts_probe) >= 0) {
                if (kcp->probe_wait < IKCP_PROBE_INIT) 
                    kcp->probe_wait = IKCP_PROBE_INIT;
                kcp->probe_wait += kcp->probe_wait / 2;
                if (kcp->probe_wait > IKCP_PROBE_LIMIT)
                    kcp->probe_wait = IKCP_PROBE_LIMIT;
                kcp->ts_probe = kcp->current + kcp->probe_wait;
                kcp->probe |= IKCP_ASK_SEND;
            }
        }
    } else {
        kcp->ts_probe = 0;
        kcp->probe_wait = 0;
    }

    // 发送窗口探测命令（WASK/WINS）
    if (kcp->probe & IKCP_ASK_SEND) {
        seg.cmd = IKCP_CMD_WASK;
        char *ptr = buffer;
        int size = (int)(ptr - buffer);
        if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
            ikcp_output(kcp, buffer, size);
            ptr = buffer;
        }
        ptr = ikcp_encode_seg(ptr, &seg);
    }

    if (kcp->probe & IKCP_ASK_TELL) {
        seg.cmd = IKCP_CMD_WINS;
        char *ptr = buffer;
        int size = (int)(ptr - buffer);
        if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
            ikcp_output(kcp, buffer, size);
            ptr = buffer;
        }
        ptr = ikcp_encode_seg(ptr, &seg);
    }
    kcp->probe = 0;

    // 计算拥塞窗口并移动数据从发送队列到发送缓冲区
    IUINT32 cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd);
    if (kcp->nocwnd == 0) cwnd = _imin_(kcp->cwnd, cwnd);

    // 当发送窗口未满时，继续从发送队列中取出数据包并准备发送
    while (_itimediff(kcp->snd_nxt, kcp->snd_una + cwnd) < 0) {
        // 如果发送队列为空，则跳出循环
        if (iqueue_is_empty(&kcp->snd_queue)) break;
        
        // 从发送队列中获取下一个数据包，并将其从队列中移除
        IKCPSEG *newseg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
        iqueue_del(&newseg->node);
        
        // 将数据包添加到发送缓冲区尾部
        iqueue_add_tail(&newseg->node, &kcp->snd_buf);
        kcp->nsnd_que--;
        kcp->nsnd_buf++;
        
        // 初始化数据包的头部信息
        newseg->conv = kcp->conv;
        newseg->cmd = IKCP_CMD_PUSH;
        newseg->wnd = seg.wnd;
        newseg->ts = kcp->current;
        newseg->sn = kcp->snd_nxt++;
        newseg->una = kcp->rcv_nxt;
        newseg->resendts = kcp->current;
        newseg->rto = kcp->rx_rto;
        newseg->fastack = 0;
        newseg->xmit = 0;
    }
	
    // 遍历发送缓冲区中的所有数据段，决定哪些需要发送
    for (struct IQUEUEHEAD *p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
        // 获取当前数据段
        IKCPSEG *segment = iqueue_entry(p, IKCPSEG, node);
        int needsend = 0;
    
        // 如果数据段尚未发送，则标记为需要发送，并初始化重传相关参数
        if (segment->xmit == 0) {
            needsend = 1;
            segment->xmit++;
            segment->rto = kcp->rx_rto;
            segment->resendts = kcp->current + segment->rto + rtomin;
        // 如果当前时间超过重传时间戳，则标记为需要发送，并更新重传参数
        } else if (_itimediff(kcp->current, segment->resendts) >= 0) {
            needsend = 1;
            segment->xmit++;
            kcp->xmit++;
            if (kcp->nodelay == 0) {
                segment->rto += _imax_(segment->rto, (IUINT32)kcp->rx_rto);
            } else {
                IINT32 step = (kcp->nodelay < 2)? ((IINT32)(segment->rto)) : kcp->rx_rto;
                segment->rto += step / 2;
            }
            segment->resendts = kcp->current + segment->rto;
            lost = 1;
        // 如果数据段的快速确认次数达到重传阈值，并且快速重传次数未超过限制，则标记为需要发送
        } else if (segment->fastack >= resent) {
            if ((int)segment->xmit <= kcp->fastlimit || kcp->fastlimit <= 0) {
                needsend = 1;
                segment->xmit++;
                segment->fastack = 0;
                segment->resendts = kcp->current + segment->rto;
                change++;
            }
        }
    
        // 如果数据段需要发送，则进行发送处理
        if (needsend) {
            char *ptr = buffer;
            int size = (int)(ptr - buffer);
            int need = IKCP_OVERHEAD + segment->len;
    
            // 如果当前缓冲区不足以容纳新的数据段，则先发送当前缓冲区的数据
            if (size + need > (int)kcp->mtu) {
                ikcp_output(kcp, buffer, size);
                ptr = buffer;
            }
    
            // 编码数据段并添加到发送缓冲区
            ptr = ikcp_encode_seg(ptr, segment);
    
            // 如果数据段包含数据，则复制数据到发送缓冲区
            if (segment->len > 0) {
                memcpy(ptr, segment->data, segment->len);
                ptr += segment->len;
            }
    
            // 如果数据段的发送次数超过死亡链接阈值，则标记KCP状态为死亡
            if (segment->xmit >= kcp->dead_link) {
                kcp->state = (IUINT32)-1;
            }
        }
    }
    // 发送剩余的数据段
    int size = (int)(ptr - buffer);
    if (size > 0) {
        ikcp_output(kcp, buffer, size);
    }

    // 更新拥塞窗口和慢启动阈值
    if (change) {
        IUINT32 inflight = kcp->snd_nxt - kcp->snd_una;
        kcp->ssthresh = inflight / 2;
        if (kcp->ssthresh < IKCP_THRESH_MIN)
            kcp->ssthresh = IKCP_THRESH_MIN;
        kcp->cwnd = kcp->ssthresh + resent;
        kcp->incr = kcp->cwnd * kcp->mss;
    }

    if (lost) {
        kcp->ssthresh = cwnd / 2;
        if (kcp->ssthresh < IKCP_THRESH_MIN)
            kcp->ssthresh = IKCP_THRESH_MIN;
        kcp->cwnd = 1;
        kcp->incr = kcp->mss;
    }

    if (kcp->cwnd < 1) {
        kcp->cwnd = 1;
        kcp->incr = kcp->mss;
    }
}

//---------------------------------------------------------------------
// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec. 
//---------------------------------------------------------------------
/**
 * 更新KCP协议控制块的状态
 * 
 * @param kcp 指向KCP控制块的指针
 * @param current 当前时间戳
 * 
 * 此函数主要用于根据当前时间戳更新KCP控制块的状态，包括更新时间戳、检查是否需要刷新数据等
 */
void ikcp_update(ikcpcb *kcp, IUINT32 current)
{
    // 定义一个整型变量slap用于计算时间差
    IINT32 slap;

    // 更新KCP控制块中的当前时间戳
    kcp->current = current;

    // 如果KCP控制块尚未被更新过
    if (kcp->updated == 0) {
        // 标记为已更新
        kcp->updated = 1;
        // 初始化刷新时间戳为当前时间
        kcp->ts_flush = kcp->current;
    }

    // 计算当前时间与上次刷新时间的时间差
    slap = _itimediff(kcp->current, kcp->ts_flush);

    // 如果时间差大于等于10000毫秒或小于-10000毫秒，可能是时间回绕，需要重置刷新时间戳
    if (slap >= 10000 || slap < -10000) {
        kcp->ts_flush = kcp->current;
        slap = 0;
    }

    // 如果时间差大于等于0，说明到了刷新数据的时候
    if (slap >= 0) {
        // 计算下一次刷新时间
        kcp->ts_flush += kcp->interval;
        // 如果当前时间已经超过了下一次刷新时间，调整刷新时间为当前时间加上间隔
        if (_itimediff(kcp->current, kcp->ts_flush) >= 0) {
            kcp->ts_flush = kcp->current + kcp->interval;
        }
        // 调用刷新函数处理数据
        ikcp_flush(kcp);
    }
}


//---------------------------------------------------------------------
// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
//---------------------------------------------------------------------
IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current)
{
	IUINT32 ts_flush = kcp->ts_flush;
	IINT32 tm_flush = 0x7fffffff;
	IINT32 tm_packet = 0x7fffffff;
	IUINT32 minimal = 0;
	struct IQUEUEHEAD *p;

	if (kcp->updated == 0) {
		return current;
	}

	if (_itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000) {
		ts_flush = current;
	}

	if (_itimediff(current, ts_flush) >= 0) {
		return current;
	}

	tm_flush = _itimediff(ts_flush, current);

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		IINT32 diff = _itimediff(seg->resendts, current);
		if (diff <= 0) {
			return current;
		}
		if (diff < tm_packet) tm_packet = diff;
	}

	minimal = (IUINT32)(tm_packet < tm_flush ? tm_packet : tm_flush);
	if (minimal >= kcp->interval) minimal = kcp->interval;

	return current + minimal;
}



int ikcp_setmtu(ikcpcb *kcp, int mtu)
{
	char *buffer;
	if (mtu < 50 || mtu < (int)IKCP_OVERHEAD) 
		return -1;
	buffer = (char*)ikcp_malloc((mtu + IKCP_OVERHEAD) * 3);
	if (buffer == NULL) 
		return -2;
	kcp->mtu = mtu;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	ikcp_free(kcp->buffer);
	kcp->buffer = buffer;
	return 0;
}

int ikcp_interval(ikcpcb *kcp, int interval)
{
	if (interval > 5000) interval = 5000;
	else if (interval < 10) interval = 10;
	kcp->interval = interval;
	return 0;
}

/**
 * 设置KCP协议的无延迟模式及相关参数
 * 
 * @param kcp KCP协议控制块指针，用于管理KCP协议的状态和配置
 * @param nodelay 是否启用无延迟模式，1为启用，0为禁用
 * @param interval 更新间隔，单位为毫秒，用于控制KCP协议的更新频率
 * @param resend 快速重发的副本数，用于提高数据传输的可靠性
 * @param nc 是否禁用拥塞控制，1为禁用，0为启用
 * @return 固定返回0，表示函数执行完毕
 * 
 * 此函数允许用户配置KCP协议的无延迟模式、更新间隔、快速重发和拥塞控制等参数，
 * 以优化数据传输的实时性和可靠性
 */
int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc)
{
    // 设置无延迟模式
    if (nodelay >= 0) {
        kcp->nodelay = nodelay;
        if (nodelay) {
            kcp->rx_minrto = IKCP_RTO_NDL;    // 启用无延迟模式时，设置最小重传时间为无延迟模式下的值
        } else {
            kcp->rx_minrto = IKCP_RTO_MIN;    // 不启用无延迟模式时，设置最小重传时间为正常模式下的最小值
        }
    }
    
    // 设置更新间隔
    if (interval >= 0) {
        if (interval > 5000) interval = 5000;  // 限制更新间隔的最大值为5000毫秒
        else if (interval < 10) interval = 10; // 限制更新间隔的最小值为10毫秒
        kcp->interval = interval;              // 设置更新间隔
    }
    
    // 设置快速重发的副本数
    if (resend >= 0) {
        kcp->fastresend = resend;
    }
    
    // 设置是否禁用拥塞控制
    if (nc >= 0) {
        kcp->nocwnd = nc;
    }
    
    return 0; // 函数执行完毕，固定返回0
}


int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd)
{
	if (kcp) {
		if (sndwnd > 0) {
			kcp->snd_wnd = sndwnd;
		}
		if (rcvwnd > 0) {   // must >= max fragment size
			kcp->rcv_wnd = _imax_(rcvwnd, IKCP_WND_RCV);
		}
	}
	return 0;
}

/**
 * 获取等待发送的数据包数量
 * 
 * @param kcp 指向IKCP协议控制块的指针，用于接收和发送数据包
 * @return 返回等待发送（包括缓冲区和队列中）的数据包总数
 * 
 * 此函数用于获取当前等待发送的数据包数量，包括已经在缓冲区中等待发送的数据包
 * 以及已经在发送队列中排队等待发送的数据包。这有助于应用程序了解当前的发送压力
 * 或者用于控制发送速率等目的。
 */
int ikcp_waitsnd(const ikcpcb *kcp)
{
    // 返回等待发送的数据包总数，包括缓冲区中的数据包和队列中的数据包
    return kcp->nsnd_buf + kcp->nsnd_que;
}


// read conv
IUINT32 ikcp_getconv(const void *ptr)
{
	IUINT32 conv;
	ikcp_decode32u((const char*)ptr, &conv);
	return conv;
}
