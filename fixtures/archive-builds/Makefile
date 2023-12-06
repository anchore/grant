PKGSDIR=packages

ifndef PKGSDIR
    $(error PKGSDIR is not set)
endif

clean: clean-examples
	rm -f $(PKGSDIR)/*

jars: $(PKGSDIR)/example-java-app-maven-0.1.0.jar

archives: $(PKGSDIR)/example-java-app-maven-0.1.0.zip

$(PKGSDIR)/example-java-app-maven-0.1.0.zip: $(PKGSDIR)/example-java-app-maven-0.1.0.jar
	zip $(PKGSDIR)/example-java-app-maven-0.1.0.zip $(PKGSDIR)/example-java-app-maven-0.1.0.jar

# Maven...
$(PKGSDIR)/example-java-app-maven-0.1.0.jar:
	./build-example-java-app-maven.sh $(PKGSDIR)