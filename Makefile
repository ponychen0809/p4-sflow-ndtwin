
build:
	~/p4_build.sh sflow.p4

run:
	git pull
	~/p4_build.sh sflow.p4
	${SDE}/run_switchd.sh -p sflow

bfrt:
	${SDE}/run_switchd.sh -p sflow

test:
	${SDE}/run_p4_tests.sh -p sflow -t ./ -s sflow_manager.SimpleSwitchTest -f ./ports.json

clear:
	rm -f *log*
	rm -f ptf.pcap
	rm -rf __pycache__