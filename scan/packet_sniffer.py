import argparse
from collections import namedtuple
import datetime as dt
from enum import Enum
import json
import os
import re
import sys

from progressbar import ProgressBar, Counter, Percentage, Bar, Timer
from scapy.all import *

Result = namedtuple('Result', 'response msg data')
Result.__new__.__defaults__ = (None,) * len(Result._fields)


class Response(Enum):
    OK = True
    ERROR = False
    NOREPLY = None
    INTERRUPT = 1


class PacketSniffer():
    def __init__(self, pcap, packets, exclude_metadata=False,
                 location="somewhere", notes="", metadata_outfile=None,
                 output_loc=None):
        self.pcap = pcap
        self.packets = packets
        self.exlcude_metdata = exclude_metadata
        self.location = location
        self.notes = notes
        self.metadata_outfile = metadata_outfile
        self.output_loc = output_loc
        self.sniff_start = None
        self.sniff_end = None
        self.packets_sniffed = 0
        self.logger = logging.getLogger(__name__)

    def sniff(self):
        self.packets_sniffed = 0
        self.sniff_start = dt.datetime.now()

        widgets = ['Received: ', Counter(), ' packets (',
                   Timer(), ')', Percentage(), Bar()]
        pbar = ProgressBar(widgets=widgets, maxval=args.packets).start()
        def update_pbar(_):
            self.packets_sniffed += 1
            pbar.update(pbar.currval + 1)

        try:
            pkts = sniff(count=args.packets, prn=update_pbar)
            if self.packets_sniffed < self.packets:
                raise KeyboardInterrupt()
            self.sniff_end = dt.datetime.now()
            pbar.finish()

            return Result(Response.OK, data=pkts)
        except KeyboardInterrupt:
            self.packets = pbar.currval
            self.sniff_end = dt.datetime.now()
            pbar.finish()
            return Result(
                response=Response.INTERRUPT,
                msg="Caught keyboard interrupt",
                data=pkts
            )
        except Exception as e:
            return Result(Response.ERROR, f"Error sniffing: {e.args}")

    def write_data(self, packets):
        try:
            outfile = self.pcap
            if self.output_loc:
                assert os.path.isdir(self.output_loc)
                outfile = os.path.join(self.output_loc, self.pcap)
            wrpcap(outfile, packets)
            return Result(
                Response.OK,
                f"wrote {self.packets} packets to {self.pcap}"
            )
        except Exception as e:
            return Result(Response.ERROR, f"Error writing pcap: {e}")

    def _create_metadata_outfile(self):
        location = re.sub("\s+", "_", self.location)  
        return f"{location}__{self.sniff_start.strftime('%Y%m%d_%H_%M')}.json"

    def write_metadata(self):
        if self.exlcude_metdata:
            return Result(Response.NOREPLY, "")
        outfile = self.metadata_outfile 

        if not outfile:
            outfile = self._create_metadata_outfile()
        elif os.path.isdir(outfile):
            outfile = os.path.join(outfile, self._create_metadata_outfile())

        output = dict(
            start=self.sniff_start.astimezone().isoformat(),
            end=self.sniff_end.astimezone().isoformat(),
            location=self.location,
            pcap=self.pcap,
            number_of_packets_captured=self.packets
        )
        try:
            if self.notes:
                output["notes"] = self.notes

            with open(outfile, "w") as f:
                json.dump(output, f, indent=4)
            return Result(Response.OK, f"wrote metadata to {outfile}")
        except Exception as e:
            return Result(Response.ERROR, f"Error writing metadata: {e}")


if __name__ == '__main__':
    setup_logging()
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(prog="packet_sniffer")
    parser.add_argument('pcap', metavar='pcap-output-file')
    parser.add_argument('packets', type=int)
    parser.add_argument('-x', '--exclude-metadata', action="store_true")
    parser.add_argument('-l', '--location', default="somewhere", action="store")
    parser.add_argument('-m', '--metadata-outfile', action="store")
    parser.add_argument("-n", "--notes", action="store")
    parser.add_argument("-o", "--output-loc", action="store")
    args = parser.parse_args()

    if args.exclude_metadata:
        if args.metadata_outfile or args.location != args.location.default:
            raise parser.error(
                "Exclude-metadata argument cannot be combined with metadata "
                "arguments (ie. \n\t- [-m, --exclude-metadata],\n\t"
                "- [-l, --location],\n\t- [-n, --notes],\n)"
            )

    if args.output_loc:
        try:
            assert os.path.isdir(args.output_loc)
        except AssertionError:
            if os.path.isdir(os.path.dirname(args.output_loc)):
                raise parser.error(
                    f"{os.path.dirname(args.output_loc)} exists, but "
                    f"{args.output_loc} does not. Try re-running with "
                    f" pcap={os.path.basename(args.output_loc)} and "
                    f"-o {os.path.dirname(args.output_loc)}"
                )
            else:
                raise parser.error(
                    f"Output location: {args.output_loc} does not exist."
                )

    pktsniffer = PacketSniffer(**vars(args))
    res = pktsniffer.sniff()

    if res.response:
        if res.response == Response.INTERRUPT:
            logger.debug(f"Interrput message received, response={res}")
            print(res.msg)

        mdres = pktsniffer.write_metadata()
        dres = pktsniffer.write_data(res.data)

        if mdres.response == Response.OK and dres.response == Response.OK:
            print(f"Successfully {dres.msg} and {mdres.msg}.")
        elif mdres.response == Response.NOREPLY:
            print(f"Successfully {dres.msg}")
        else:
            print(
                "Error encountered: "
                "\n".join([r.msg for r in [dres, mdres]
                                 if r.response == Response.ERROR])
            )
    else:
        print("Error encountered: " + res.msg)

