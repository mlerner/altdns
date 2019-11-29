import threading
import time
import datetime
from threading import Lock
from queue import Queue as Queue

import tldextract
from tldextract.tldextract import LOG
import logging
from termcolor import colored
import dns.resolver
import re
import os

logging.basicConfig(level=logging.CRITICAL)


def get_alteration_words(wordlist_filename):
    with open(wordlist_filename, "r") as f:
        return f.readlines()


# will write to the file if the check returns true
def write_domain(wp, full_url):
    wp.write(full_url)


# function inserts words at every index of the subdomain
def insert_all_indexes(input_filename, output_tmp_filename, alteration_words):
    with open(input_filename, "r") as fp:
        with open(output_tmp_filename, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in alteration_words:
                    for index in range(0, len(current_sub)):
                        current_sub.insert(index, word.strip())
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        if actual_sub[-1:] is not ".":
                            write_domain(wp, full_url)
                        current_sub.pop(index)
                    current_sub.append(word.strip())
                    actual_sub = ".".join(current_sub)
                    full_url = "{0}.{1}.{2}\n".format(actual_sub, ext.domain,
                                                      ext.suffix)
                    if len(current_sub[0]) > 0:
                        write_domain(wp, full_url)
                    current_sub.pop()


# adds word-NUM and wordNUM to each subdomain at each unique position
def insert_number_suffix_subdomains(input_filename, output_tmp_filename,
                                    alternation_words):
    with open(input_filename, "r") as fp:
        with open(output_tmp_filename, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in range(0, 10):
                    for index, value in enumerate(current_sub):
                        #add word-NUM
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[index] + "-" + str(
                            word)
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        write_domain(wp, full_url)
                        current_sub[index] = original_sub

                        #add wordNUM
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[index] + str(word)
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        write_domain(wp, full_url)
                        current_sub[index] = original_sub


# adds word- and -word to each subdomain at each unique position
def insert_dash_subdomains(input_filename, output_tmp_filename,
                           alteration_words):
    with open(input_filename, "r") as fp:
        with open(output_tmp_filename, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in alteration_words:
                    for index, value in enumerate(current_sub):
                        original_sub = current_sub[index]
                        current_sub[
                            index] = current_sub[index] + "-" + word.strip()
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        if len(current_sub[0]
                               ) > 0 and actual_sub[:1] is not "-":
                            write_domain(wp, full_url)
                        current_sub[index] = original_sub
                        # second dash alteration
                        current_sub[index] = word.strip() + "-" + \
                            current_sub[index]
                        actual_sub = ".".join(current_sub)
                        # save second full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        if actual_sub[-1:] is not "-":
                            write_domain(wp, full_url)
                        current_sub[index] = original_sub


# adds prefix and suffix word to each subdomain
def join_words_subdomains(input_filename, output_tmp_filename,
                          alteration_words):
    with open(input_filename, "r") as fp:
        with open(output_tmp_filename, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in alteration_words:
                    for index, value in enumerate(current_sub):
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[index] + word.strip()
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        write_domain(wp, full_url)
                        current_sub[index] = original_sub
                        # second dash alteration
                        current_sub[index] = word.strip() + current_sub[index]
                        actual_sub = ".".join(current_sub)
                        # save second full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        write_domain(wp, full_url)
                        current_sub[index] = original_sub


def get_cname(q, target, resolved_out):

    global progress
    global lock
    global starttime
    global found
    global resolverName
    lock.acquire()
    progress += 1
    lock.release()
    if progress % 500 == 0:
        lock.acquire()
        left = linecount - progress
        secondspassed = (int(time.time()) - starttime) + 1
        amountpersecond = progress / secondspassed
        lock.release()
        seconds = 0 if amountpersecond == 0 else int(left / amountpersecond)
        timeleft = str(datetime.timedelta(seconds=seconds))
        print(
            colored(
                "[*] {0}/{1} completed, approx {2} left".format(
                    progress, linecount, timeleft), "blue"))
    final_hostname = target
    result = list()
    result.append(target)
    resolver = dns.resolver.Resolver()
    if (resolverName is
            not None):  #if a DNS server has been manually specified
        resolver.nameservers = [resolverName]
    try:
        for rdata in resolver.query(final_hostname, 'CNAME'):
            result.append(rdata.target)
    except:
        pass
    if len(result) is 1:
        try:
            A = resolver.query(final_hostname, "A")
            if len(A) > 0:
                result = list()
                result.append(final_hostname)
                result.append(str(A[0]))
        except:
            pass
    if len(result) > 1:  #will always have 1 item (target)
        if str(result[1]) in found:
            if found[str(result[1])] > 3:
                return
            else:
                found[str(result[1])] = found[str(result[1])] + 1
        else:
            found[str(result[1])] = 1
        resolved_out.write(str(result[0]) + ":" + str(result[1]) + "\n")
        resolved_out.flush()
        ext = tldextract.extract(str(result[1]))
        if ext.domain == "amazonaws":
            try:
                for rdata in resolver.query(result[1], 'CNAME'):
                    result.append(rdata.target)
            except:
                pass
        print(colored(result[0], "red") + " : " + colored(result[1], "green"))
        if len(result) > 2 and result[2]:
            print(
                colored(result[0], "red") + " : " +
                colored(result[1], "green") + ": " +
                colored(result[2], "blue"))
    q.put(result)


def remove_duplicates(output_filename):
    with open(output_filename) as b:
        blines = set(b)
        with open(output_filename, 'w') as result:
            for line in blines:
                result.write(line)


def remove_existing(input_filename, output_tmp_filename, output_filename):
    with open(input_filename) as b:
        blines = set(b)
    with open(output_tmp_filename) as a:
        with open(output_filename, 'w') as result:
            for line in a:
                if line not in blines:
                    result.write(line)
    os.remove(output_tmp_filename)


def get_line_count(filename):
    with open(filename, "r") as lc:
        linecount = sum(1 for _ in lc)
    return linecount


def run(input_filename,
        output_filename,
        wordlist_filename,
        resolve=True,
        add_number_suffix=True,
        ignore_existing=True,
        dnsserver='8.8.8.8',
        save=False,
        threads=0):
    if resolve:
        try:
            resolved_out = open(save, "a")
        except:
            print("Please provide a file name to save results to "
                  "via the -s argument")
            raise SystemExit

    alteration_words = get_alteration_words(wordlist_filename)

    # if we should remove existing, save the output to a temporary file
    if ignore_existing is True:
        output_tmp_filename = output_filename + '.tmp'
    else:
        output_tmp_filename = output_filename

    # wipe the output before, so we fresh alternated data
    open(output_tmp_filename, 'w').close()

    insert_all_indexes(input_filename, output_tmp_filename, alteration_words)
    insert_dash_subdomains(input_filename, output_tmp_filename,
                           alteration_words)
    if add_number_suffix is True:
        insert_number_suffix_subdomains(input_filename, output_tmp_filename,
                                        alteration_words)
    join_words_subdomains(input_filename, output_tmp_filename,
                          alteration_words)

    threadhandler = []

    # Removes already existing + dupes from output
    if ignore_existing is True:
        remove_existing(input_filename, output_tmp_filename, output_filename)
    else:
        remove_duplicates(output_filename)

    q = Queue()

    if resolve:
        global progress
        global linecount
        global lock
        global starttime
        global found
        global resolverName
        lock = Lock()
        found = {}
        progress = 0
        starttime = int(time.time())
        linecount = get_line_count(output_filename)
        resolverName = dnsserver
        with open(output_filename, "r") as fp:
            for i in fp:
                if threads:
                    if len(threadhandler) > int(threads):
                        #Wait until there's only 10 active threads
                        while len(threadhandler) > 10:
                            threadhandler.pop().join()
                try:
                    t = threading.Thread(target=get_cname,
                                         args=(q, i.strip(), resolved_out))
                    t.daemon = True
                    threadhandler.append(t)
                    t.start()
                except Exception as error:
                    print("error:"), (error)
            #Wait for threads
            while len(threadhandler) > 0:
                threadhandler.pop().join()

        timetaken = str(
            datetime.timedelta(seconds=(int(time.time()) - starttime)))
        print(colored("[*] Completed in {0}".format(timetaken), "blue"))
