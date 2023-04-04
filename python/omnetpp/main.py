import argparse
import logging
import socket
import sys

from omnetpp.common.cluster import *
from omnetpp.simulation.project import *
from omnetpp.simulation.task import *
from omnetpp.test import *

__sphinx_mock__ = True # ignore this module in documentation

_logger = logging.getLogger(__name__)

def parse_run_tasks_arguments(task_name, database_required=False):
    description = "Runs all " + task_name + " concurrently in the enclosing project, recursively from the current working directory, as separate processes on localhost."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-p", "--simulation-project", default=None, help="specifies the name of the project")
    parser.add_argument("-m", "--mode", choices=["debug", "release"], help="specifies the build mode of the project")
    parser.add_argument("--build", action="store_true", help="Build executable")
    parser.add_argument("--no-build", dest="build", action="store_false")
    parser.add_argument("--concurrent", action="store_true", help="Concurrent execution")
    parser.add_argument("--no-concurrent", dest="concurrent", action="store_false")
    parser.add_argument("--dry-run", default=False, action=argparse.BooleanOptionalAction, help="displays what would be done but doesn't actually do anything")
    parser.add_argument("-u", "--user-interface", choices=["Cmdenv", "Qtenv"], default="Cmdenv", help="determines the user interface")
    parser.add_argument("-t", "--sim-time-limit", default=None, help="specifies the simulation time limit")
    parser.add_argument("-T", "--cpu-time-limit", default=None, help="specifies the CPU time limit")
    parser.add_argument("-f", "--filter", default=None, help="includes simulations that match the specified generic filter")
    parser.add_argument("--exclude-filter", default=None, help="exclude simulations that match the specified generic filter")
    parser.add_argument("-w", "--working-directory-filter", default=None, help="includes simulations from a specific working directory")
    parser.add_argument("--exclude-working-directory-filter", default=None, help="excludes simulations from a specific working directory")
    parser.add_argument("-i", "--ini-file-filter", default=None, help="includes simulations from matching INI files")
    parser.add_argument("--exclude-ini-file-filter", default=None, help="excludes simulations from matching INI files")
    parser.add_argument("-c", "--config-filter", default=None, help="includes simulations having the specified INI file config sections")
    parser.add_argument("--exclude-config-filter", default=None, help="exclude simulations having the specified INI file config sections")
    parser.add_argument("-r", "--run-number-filter", default=None, help="includes simulations having the specified run numbers")
    parser.add_argument("--exclude-run-number-filter", default=None, help="exclude simulations having the specified run numbers")
    parser.add_argument("--scheduler", choices=["process", "thread", "cluster"], default="thread", help="specifies the scheduler for concurrent simulations")
    parser.add_argument("--simulation-runner", choices=["subprocess", "inprocess"], default="subprocess", help="specifies the simulation runner for individual simulations")
    parser.add_argument("--hosts", default="localhost", help="specifies the hosts where the simulations are run")
    parser.add_argument("-x", "--nix-shell", default=None, help="specifies the NIX shell in which the simulations are run")
    parser.add_argument("-d", "--database", required=database_required, default=None, help="specifies the database where data is stored between subsequent executions, the special value 'default' means the default database")
    parser.add_argument("--store-task-result", default=True, action=argparse.BooleanOptionalAction, help="determines if task results are stored in the database")
    parser.add_argument("--store-complete-binary-hash", default=None, action=argparse.BooleanOptionalAction, help="determines if the stored task results contain the complete binary hash of simulations")
    parser.add_argument("--store-complete-source-hash", default=None, action=argparse.BooleanOptionalAction, help="determines if the stored task results contain the complete source hash of simulations")
    parser.add_argument("--store-partial-binary-hash", default=None, action=argparse.BooleanOptionalAction, help="determines if the stored task results contain the partial binary hash of simulations")
    parser.add_argument("--store-partial-source-hash", default=None, action=argparse.BooleanOptionalAction, help="determines if the stored task results contain the partial source hash of simulations")
    parser.add_argument("--restore-task-result", default=True, action=argparse.BooleanOptionalAction, help="determines if task results are restored from the database")
    parser.add_argument("--restore-by-complete-binary-hash", default=None, action=argparse.BooleanOptionalAction, help="determines if task results can be restored using the complete binary hash of simulations")
    parser.add_argument("--restore-by-complete-source-hash", default=None, action=argparse.BooleanOptionalAction, help="determines if task results can be restored using the complete source hash of simulations")
    parser.add_argument("--restore-by-partial-binary-hash", default=None, action=argparse.BooleanOptionalAction, help="determines if task results can be restored using the partial binary hash of simulations")
    parser.add_argument("--restore-by-partial-source-hash", default=None, action=argparse.BooleanOptionalAction, help="determines if task results can be restored using the partial source hash of simulations")
    parser.add_argument("-l", "--log-level", choices=["ERROR", "WARN", "INFO", "DEBUG"], default="WARN", help="specifies the log level for the root logging category")
    parser.add_argument("--handle-exception", default=True, action=argparse.BooleanOptionalAction, help="disables displaying stacktraces for exceptions")
    parser.set_defaults(concurrent=True, build=True)
    return parser.parse_args(sys.argv[1:])

def process_run_tasks_arguments(args):
    logging.getLogger("distributed.deploy.ssh").setLevel(args.log_level)
    if args.database:
        initialize_database_engine(database=args.database if args.database != "default" else default_database)
    define_sample_projects()
    simulation_project = determine_default_simulation_project(name=args.simulation_project)
    kwargs = {k: v for k, v in vars(args).items() if v is not None}
    kwargs["simulation_project"] = simulation_project
    has_filter_kwarg = False
    for k in kwargs.keys():
        has_filter_kwarg = has_filter_kwarg or k.endswith("filter")
    if not has_filter_kwarg and not args.simulation_project:
        kwargs["working_directory_filter"] = os.path.relpath(os.getcwd(), os.path.realpath(simulation_project.get_full_path(".")))
    if "working_directory_filter" in kwargs:
        kwargs["working_directory_filter"] = re.sub("(.*)/$", "\\1", kwargs["working_directory_filter"])
    if args.simulation_runner == "inprocess":
        import omnetpp.simulation.cffi
    del kwargs["hosts"]
    if args.hosts != "localhost" and args.hosts != socket.gethostname():
        worker_hostnames = args.hosts.split(",")
        scheduler_hostname = worker_hostnames[0]
        simulation_project.copy_binary_simulation_distribution_to_cluster(worker_hostnames)
        cluster = SSHCluster(scheduler_hostname, worker_hostnames, nix_shell=args.nix_shell)
        cluster.start()
        kwargs["scheduler"] = "cluster"
        kwargs["cluster"] = cluster
    return kwargs

def run_tasks_main(main_function, task_name, database_required=False):
    try:
        args = parse_run_tasks_arguments(task_name, database_required=database_required)
        initialize_logging(args.log_level)
        _logger.debug(f"Processing command line arguments: {args}")
        kwargs = process_run_tasks_arguments(args)
        _logger.debug(f"Calling main function with: {kwargs}")
        result = main_function(**kwargs)
        _logger.debug(f"Main function returned: {result}")
        print(result)
        sys.exit(0 if (result is None or result.is_all_results_expected()) else 1)
    except KeyboardInterrupt:
        _logger.warn("Program interrupted by user")
    except Exception as e:
        if args.handle_exception:
            _logger.error(str(e))
        else:
            raise e

def run_simulations_main():
    run_tasks_main(run_simulations, "simulations")

def run_smoke_tests_main():
    run_tasks_main(run_smoke_tests, "smoke tests")

def run_fingerprint_tests_main():
    run_tasks_main(run_fingerprint_tests, "fingerprint tests", database_required=True)

def update_correct_fingerprints_main():
    run_tasks_main(update_correct_fingerprints, "update correct fingerprints", database_required=True)

def parse_build_project_arguments():
    description = "Builds the specified or enclosing simulation project."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-p", "--simulation-project", default=None, help="specifies the name of the project")
    parser.add_argument("-m", "--mode", choices=["debug", "release"], help="specifies the build mode of the project")
    parser.add_argument("--concurrent", default=True, action=argparse.BooleanOptionalAction, help="determines if multiple tasks are run concurrently or not")
    parser.add_argument("-l", "--log-level", choices=["ERROR", "WARN", "INFO", "DEBUG"], default="WARN", help="specifies the log level for the root logging category")
    parser.add_argument("--handle-exception", default=True, action=argparse.BooleanOptionalAction, help="disables displaying stacktraces for exceptions")
    return parser.parse_args(sys.argv[1:])

def process_build_project_arguments(args):
    initialize_logging(args.log_level)
    define_sample_projects()
    simulation_project = determine_default_simulation_project(name=args.simulation_project)
    kwargs = {k: v for k, v in vars(args).items() if v is not None}
    kwargs["simulation_project"] = simulation_project
    return kwargs

def build_project_main():
    try:
        args = parse_build_project_arguments()
        kwargs = process_build_project_arguments(args)
        result = build_project_using_tasks(**kwargs)
        print(result)
        sys.exit(0 if (result is None or result.is_all_results_expected()) else 1)
    except KeyboardInterrupt:
        _logger.warn("Program interrupted by user")
    except Exception as e:
        if args.handle_exception:
            _logger.error(str(e))
        else:
            raise e
