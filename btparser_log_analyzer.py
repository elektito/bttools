#!/usr/bin/env python

import bencode

import hashlib
import argparse
import re
from collections import defaultdict

new_file_re = re.compile('\\[INFO\\]\t\\[NEW FILE\\] (.+)')
infohash_re = re.compile('\\[INFO\\]\tinfohash: (.+)')
piece_re = re.compile('\\[INFO\\]\t\\[MESSAGE\\] PIECE: index=(\\d+) begin=(\\d+) length=(\\d+)')
error_re = re.compile('\\[ERROR\\]\t(.+)')
warning_re = re.compile('\\[WARNING\\]\t(.+)')
ending_re = re.compile('\\[INFO\\]\t(\\d+) bytes of piece data in a stream of (\\d+) bytes\\.')

args = None
files = {}
all_pieces = defaultdict(list)
infos = {}

def parse_section(lines, n):
    result = new_file_re.match(lines[n][:-1])
    filename = result.group(1)

    pieces = []
    errors = []
    infohash = ''

    while n < len(lines):
        n += 1
        l = lines[n][:-1]

        result = piece_re.match(l)
        if result:
            index, begin, length = result.groups()
            index = int(index)
            begin = int(begin)
            length = int(length)
            pieces.append((index, begin, length))
            continue

        result = infohash_re.match(l)
        if result:
            infohash = result.group(1)
            continue

        result = error_re.match(l)
        if result:
            errors.append(result.group(1))
            continue

        result = warning_re.match(l)
        if result:
            errors.append(result.group(1))
            continue

        result = ending_re.match(l)
        if result:
            piece_bytes = int(result.group(1))
            total_bytes = int(result.group(2))
            if 'Stream does not contain BitTorrent data.' not in errors:
                if total_bytes > args.ignore_small:
                    if args.ignore_big == 0 or (args.ignore_big > 0 and total_bytes < args.ignore_big):
                        files[filename] = piece_bytes, total_bytes, infohash, pieces, errors

            n += 1
            break

    return n

def output_piece_info():
    global all_pieces

    unknown_infohashes = {infohash
                          for (index, infohash), blocks in all_pieces.items()
                          if infohash not in infos}
    known_infohashes = {infohash
                        for (index, infohash), blocks in all_pieces.items()
                        if infohash in infos}

    for infohash in unknown_infohashes:
        print 'Can\'t produce piece stats for unknown infohash: {}'.format(infohash)
        all_pieces = {(index, infohash): blocks
                      for (index, infohash), blocks in all_pieces.items()
                      if infohash != infohash}

        print infos.keys()

    if len(unknown_infohashes) > 0:
        print

    # iterate over all of the encountered pieces, sorted by the
    # piece index and the infohash.
    for (index, infohash), blocks in sorted(all_pieces.items(), key=lambda r: (r[0], r[1])):
        print '[{}][PIECE {}]'.format(infohash, index)

        print 'Total bytes:\t{:,}'.format(
            sum(length for begin, length in blocks))

        # remove duplicated blocks
        blocks = list(set(blocks))

        # sort by 'begin'
        blocks.sort(key=lambda r: r[0])

        # how much of the piece is downloaded?
        completed = sum(i[1] for i in blocks)

        piece_length = infos[infohash]['piece length']
        print 'Completed:\t{:,}/{:,}'.format(completed, piece_length)

        # construct the progress bar.
        if len(blocks) > 1:
            block_size = blocks[0][1]
        elif len(blocks) == 1 and blocks[0][0] < piece_length - 2**14:
            block_size = blocks[0][1]
        else:
            # can't deduce block size because this single block might
            # be the last block and smaller than the normal block
            # size.
            block_size = 0
        if block_size > 0:
            pbar = ''.join('#' if len([0 for i in blocks if i[0] == n]) > 0 else '-'
                           for n in xrange(0, piece_length, block_size))
            print 'Progress:\t[{}]'.format(pbar)

        print

def main():
    parser = argparse.ArgumentParser(
        description='Parses and analyzes btparser logs.')
    parser.add_argument(
        'input',
        help='The log file to analyze.')
    parser.add_argument(
        '--ignore-small', type=int, default=68, metavar='BYTES',
        help='Ignore small files. The maximum size of a file that is '
        'considered small must be passed as an argument to this. '
        'Defaults to 68.')
    parser.add_argument(
        '--ignore-big', type=int, default=0, metavar='BYTES',
        help='Ignore big files. The minimum size of a file that is '
        'considered big must be passed as an argument to this. '
        'By default there is no limit.')
    parser.add_argument(
        '--torrent', '-t', type=str, metavar='TORRENT_FILE', action='append',
        help='Use the given torrent file to get torrent metadata. '
        'Can be specified multiple times.')
    parser.add_argument(
        '--no-piece-info', action='store_true', default=False,
        help='Don\'t output detailed piece information.')

    global args
    args = parser.parse_args()

    if args.ignore_small < 0:
        print 'Invalid file size: {}'.format(args.ignore_small)
        exit(1)

    if args.ignore_big < 0:
        print 'Invalid file size: {}'.format(args.ignore_big)
        exit(1)

    if args.torrent:
        for tf in args.torrent:
            with open(tf) as f:
                info = bencode.bdecode(f.read())['info']
                infos[hashlib.sha1(bencode.bencode(info)).digest().encode('hex')] = info

    with open(args.input) as log_file:
        lines = log_file.readlines()

    i = 0
    if lines[i][:-1] == '[WARNING]\tNo torrent files specified.':
        i += 1
    while i < len(lines):
        i = parse_section(lines, i)

    total_bytes_in_all_files = 0
    piece_bytes_in_all_files = 0
    n = 1
    for filename, info in files.items():
        piece_bytes, total_bytes, infohash, pieces, errors = info

        pieces_str = ', '.join(
            str(i) for i in sorted(j for j in set(k[0] for k in pieces)))
        pieces_str = 'None' if pieces_str == '' else pieces_str

        for index, begin, length in pieces:
            all_pieces[index, infohash].append((begin, length))

        print '[FILE {}] {}'.format(n, filename)
        print 'Infohash: {}'.format(infohash)
        print 'Piece data/Total: {}/{}'.format(piece_bytes, total_bytes)
        print 'Pieces Encountered: {}'.format(pieces_str)
        if 'Message length is over 16393. Possibly corrupt.' in errors:
            print 'Suspiciously large last piece. Possibly corrupt file.'
        if 'Unexpected end of stream.' in errors:
            print 'Stream ended unexpectedly.'
        print

        piece_bytes_in_all_files += piece_bytes
        total_bytes_in_all_files += total_bytes
        n += 1

    if not args.no_piece_info:
        output_piece_info()

    print '{:,} bytes of piece data extracted out of {:,} bytes in {} files processed.'.format(
        piece_bytes_in_all_files,
        total_bytes_in_all_files,
        len(files))

if __name__ == '__main__':
    main()
