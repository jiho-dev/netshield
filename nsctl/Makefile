
CC = gcc
CFLAGS = -Wall -g
OBJ_DIR = obj

HSLIB_DIR=../libhypersplit

INC_DIR = -I./ -I../kmod/include
INC_DIR+= -I$(HSLIB_DIR)
CFLAGS += $(INC_DIR)

LIB_DIR+= -L$(HSLIB_DIR)
LIBS = -lhs -ljson-c

LDFLAGS += $(LIB_DIR) -Wl,-rpath=$(HSLIB_DIR)

BIN = nsctl
SRC=build_hs.c  ioctl.c  main.c  parse_policy_json.c
DEP = $(patsubst %.c, $(OBJ_DIR)/%.d, $(SRC))
OBJ = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRC))

all: tag $(BIN) #run_pc

custom: upload

ifneq "$(MAKECMDGOALS)" "clean"
    -include $(DEP)
endif

$(OBJ_DIR)/%.o: %.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.d: %.c
	@set -e; rm -f $@; [ ! -e $(dir $@) ] & mkdir -p $(dir $@); \
	$(CC) -M -MT $(patsubst %.d, %.o, $@) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$;

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -rf $(OBJ_DIR);
	rm -f $(BIN) tags

tag:
	ctags -R

run_grp:
	./bin/pc_plat -g rfg -f wustl -r rule_trace/rules/origin/fw1_10K

upload:
	sshpass -proot123 scp -o StrictHostKeyChecking=no ${BIN} root@10.1.1.3:~/

run_pc:
#	./bin/pc_plat -p hs -f wustl_g -r rule_trace/rules/rfg/fw1_10K -t rule_trace/traces/fw1_10K_trace
#	./bin/pc_plat -g rfg -f wustl -r rule_trace/rules/origin/fw1_10K
#	./bin/pc_plat -p hs -f wustl -r rule_trace/rules/origin/acl1_10K -t rule_trace/traces/acl1_10K_trace
#	$(BIN) -r rule_trace/rules/origin/fw1_10K -t rule_trace/traces/fw1_10K_trace
#	./$(BIN) -p hs -f wustl -r rule_trace/rules/origin/fw2 -t rule_trace/traces/fw2_trace
#	gdb -ex=r --args ./bin/pc_plat -p hs -f wustl -r rule_trace/rules/origin/fw2 -t rule_trace/traces/origin/fw2_trace
#	gdb -ex=r --args $(BIN) -r rule_trace/rules/origin/fw1_10K -k
#	$(BIN) -r rule_trace/rules/origin/fw1_10K -k
#	$(BIN) -r rule_trace/rules/origin/fw2 -k
#	$(BIN) -r rule_trace/rules/origin/fw2
	$(BIN) -r ns_rule.txt
#	$(BIN) -r ns_rule1.txt

format: $(SRC)
	 uncrustify --no-backup --mtime -c ./formatter.cfg $^
