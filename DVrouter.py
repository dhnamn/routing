from router import Router
from packet import Packet
import json


class DVrouter(Router):
    def __init__(self, addr, heartbeat_time):
        # Initialize router state, routing table, neighbors, timers
        super().__init__(addr)
        self.addr = addr
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.infinity = 16

        # routing_table: dest -> {cost, next_hop, exit_port}
        self.routing_table = {
            addr: {"cost": 0, "next_hop": addr, "exit_port": None}
        }

        # neighbors: addr -> {exit_port, cost}
        self.neighbors = {}

    def _broadcast_routing_table(self):
        # Broadcast routing table to neighbors with poison reverse
        for neighbor, info in self.neighbors.items():
            port = info["exit_port"]
            advertised_routes = {}

            for dest, route in self.routing_table.items():
                cost = route["cost"]
                next_hop = route["next_hop"]

                # poison reverse
                if dest != neighbor and next_hop == neighbor:
                    advertised_routes[dest] = {"cost": self.infinity}
                else:
                    advertised_routes[dest] = {"cost": cost}

            pkt = Packet(Packet.ROUTING, self.addr, neighbor)
            pkt.content = json.dumps(advertised_routes)
            self.send(port, pkt)

    def _update_routing_table(self, src, received_routes):
        # Update routing table based on received routes; return True if changed
        changed = False
        if src not in self.neighbors:
            return False

        port = self.neighbors[src]["exit_port"]
        neighbor_cost = self.neighbors[src]["cost"]

        for dest, info in received_routes.items():
            rcv_cost = info["cost"]
            if rcv_cost >= self.infinity:
                # mark unreachable routes via src
                if dest in self.routing_table and self.routing_table[dest]["next_hop"] == src:
                    self.routing_table[dest] = {
                        "cost": self.infinity,
                        "next_hop": None,
                        "exit_port": None
                    }
                    changed = True
                continue

            total_cost = min(rcv_cost + neighbor_cost, self.infinity)

            current = self.routing_table.get(dest)
            if (not current) or (total_cost < current["cost"]) or (
                current["next_hop"] == src and total_cost != current["cost"]
            ):
                self.routing_table[dest] = {
                    "cost": total_cost,
                    "next_hop": src,
                    "exit_port": port
                }
                changed = True

        return changed

    def handle_packet(self, port, packet):
        # Handle incoming packets: forward traceroute or update routing table
        if packet.is_traceroute:
            route = self.routing_table.get(packet.dst_addr)
            if route and route["cost"] < self.infinity and route["exit_port"] is not None:
                self.send(route["exit_port"], packet)
        else:
            try:
                routes = json.loads(packet.content)
                if self._update_routing_table(packet.src_addr, routes):
                    self._broadcast_routing_table()
            except Exception:
                pass

    def handle_new_link(self, port, endpoint, cost):
        # Add new neighbor link and update routing table
        self.neighbors[endpoint] = {"exit_port": port, "cost": cost}
        self.routing_table[endpoint] = {
            "cost": cost,
            "next_hop": endpoint,
            "exit_port": port
        }
        self._broadcast_routing_table()

    def handle_remove_link(self, port):
        # Remove neighbor link and invalidate affected routes
        neighbor = None
        for addr, info in self.neighbors.items():
            if info["exit_port"] == port:
                neighbor = addr
                break
        if neighbor is None:
            return

        self.neighbors.pop(neighbor, None)

        for dest in list(self.routing_table.keys()):
            if self.routing_table[dest]["next_hop"] == neighbor:
                self.routing_table[dest] = {
                    "cost": self.infinity,
                    "next_hop": None,
                    "exit_port": None
                }

        self._broadcast_routing_table()

    def handle_time(self, time_ms):
        # Periodically broadcast routing table if heartbeat elapsed
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_routing_table()

    def __repr__(self):
        # String representation of the router and its routing table
        return f"DVrouter(addr={self.addr}, table={self.routing_table})"
