package inet.showcases.emulation.mininet5;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.ethernet.Eth100M;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet.visualizer.common.IntegratedVisualizer;


network MininetNetwork
{
    parameters:
        @display("bgb=1000,400");
    submodules:
        configurator: Ipv4NetworkConfigurator {
            parameters:
                @display("p=100,100;is=s");
        }
        visualizer: IntegratedVisualizer {
            parameters:
                @display("p=100,200;is=s");
        }
        router: Router {
            parameters:
                @display("p=500,300");
        }
        host1: StandardHost {
            parameters:
                @display("p=100,300");
        }
        host2: StandardHost {
            parameters:
                @display("p=900,300");
        }
    connections allowunconnected:
        host1.ethg++ <--> Eth100M <--> router.ethg++;
        host2.ethg++ <--> Eth100M <--> router.ethg++;
}
