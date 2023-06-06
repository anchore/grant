OWNER = anchore
PROJECT = grant

TOOL_DIR = .tool
BINNY = $(TOOL_DIR)/binny
TASK = $(TOOL_DIR)/task

.DEFAULT_GOAL := make-default

## Bootstrapping targets #################################
$(BINNY):
	@mkdir -p $(TOOL_DIR)
	@curl -sSfL https://raw.githubusercontent.com/$(OWNER)/binny/main/install.sh | sh -s -- -b $(TOOL_DIR)

.PHONY: task
$(TASK) task: $(BINNY)
	$(BINNY) install task


# this is a bootstrapping catch-all, where if the target doesn't exist, we'll ensure the tools are installed and then try again
%:
	make $(TASK)
	$(TASK) $@

help: $(TASK)
	@$(TASK) -l
