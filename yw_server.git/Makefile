
SRC_DIRS = src
PACKAGE_DIRS = release

all:
	for dir in $(SRC_DIRS);\
	do \
		cd $$dir && make ; cd ..;\
	done

clean:
	for dir in $(SRC_DIRS);\
	do \
		cd $$dir && make clean; cd ..;\
	done

.PHONY:package
package:
	for dir in $(PACKAGE_DIRS);\
	do \
		cd $$dir && make ; cd ..;\
	done

