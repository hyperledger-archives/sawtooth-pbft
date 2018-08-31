# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = sawtooth-pbft
SOURCEDIR     = source
BUILDDIR      = build

HTMLDIR       = $(BUILDDIR)/html

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile pbft

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile pbft
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

pbft:
	mkdir -p $(HTMLDIR)/pbft_doc;
	cd ..; cargo doc --no-deps;
	rm -f ../target/doc/.lock;
	cp -r ../target/doc/* $(HTMLDIR)/pbft_doc;
