
TARGET	= libgy.a
INC	= -I/usr/include/libxml2
SRC	= util_alth.c util_cfg.c util_dtree.c util_kfifo.c util_lock.c util_log.c util_mem.c util_obj.c util_proc.c util_queue.c util_rq.c util_socket.c util_string.c \
	nid_common.c proto_cmpp20.c proto_cmpp30.c proto_mm7.c proto_sgip.c proto_smpp.c
OBJ	= $(SRC:.c=.o)
DEFS	= -D_REENTRANT  -D_POSIX_PTHREAD_SEMANTICS -D_GNU_SOURCE
LIBS	= -lpthread -ldl -lm -lelf -lz -lbz2 -lssl -lncurses -L/usr/lib64 -lxml2
CFLAGS  = -g -Wall $(INC) $(DEFS) 
SHARED	= -fPIC -shared -o

${TARGET}: ${OBJ}
	ar rv ${TARGET} ${OBJ};rm -f ${OBJ}
${OBJ}: ${SRC}
	gcc ${CFLAGS} -c ${SRC}
clean:
	rm -f core ${TARGET} ${OBJ}
