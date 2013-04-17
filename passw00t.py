'''TODO:
 [ ] Mark pages as unswappable containing password?
'''
import getpass
import os
import readline
import scrypt
import sys

from Crypto.Cipher import AES
from functools import partial
from struct import pack, unpack
from superpass_palm import *
from uuid import uuid4

VALIDATION_STRING='JOKERS? No, not us!'
SCRYPT_CREATE_MAXTIME=100 # ms
KEY_FILE = 'master.keys'
if len(sys.argv) != 2:
    sys.stderr.write("error: one argument required (password locker directory path)\n")
    sys.exit(1)
the_dir = sys.argv[1]

def ms_to_s(ms):
    return ms / 1000.0

def local_file(f):
    return os.path.join(the_dir, f)

def write_local_file(f, contents):
    temp_file = local_file(f + '.tmp')
    with open(temp_file, 'wb') as fd:
        fd.write(contents)
    os.rename(temp_file, local_file(f))

default_iv = '\0' * 16
def aes_encrypt_whole(key, s, iv=default_iv):
    s = pack('<Q', len(s)) + s
    iv = iv if iv is not None else default_iv

    d = AES.new(key, mode=AES.MODE_CBC, IV=iv)
    rem = len(s) % 16
    if rem:
        s += '\0' * (16 - rem)
    return d.encrypt(s)

def aes_decrypt_whole(key, s, iv=default_iv):
    iv = iv if iv is not None else default_iv

    d = AES.new(key, mode=AES.MODE_CBC, IV=iv)
    work = d.decrypt(s)

    (real_length,) = unpack('<Q', work[:8])
    work = work[8:]
    return work[:real_length]

def read_box(f):
    bs = open(local_file(f), 'rb').read()
    lb = LockBox(bs)
    assert lb.key_id == master_key_id
    clear = do_decryption(lb.ciphertext, lb.iv)
    return Box(clear)

def write_box(f, box):
    assert type(box) is Box
    m = box.dumps()
    iv = os.urandom(16)
    c = do_encryption(m, iv)
    lb = LockBox(key_id=master_key_id, iv=iv, ciphertext=c)
    write_local_file(f, lb.dumps())

keys_path = local_file(KEY_FILE)
if not os.path.isfile(keys_path):
    print "This appears to be your first time running superpass."
    pw1 = getpass.getpass("master password? ").strip()
    pw2 = getpass.getpass("again (confirm)? ").strip()
    assert pw1 == pw2, "Password did not match"
    aes_key = os.urandom(256 / 8)
    crypt_key = scrypt.encrypt(aes_key, pw1, maxtime=ms_to_s(SCRYPT_CREATE_MAXTIME))
    keys = KeyList()
    do_encryption = partial(aes_encrypt_whole, aes_key)
    do_decryption = partial(aes_decrypt_whole, aes_key)
    keys.keys.append(Key(id=uuid4().hex, schema='scrypt-{}/aes-{}'.format(SCRYPT_CREATE_MAXTIME, 256),
    box_key=crypt_key, checksum=do_encryption(VALIDATION_STRING)))
    write_local_file(KEY_FILE, keys.dumps())
    master_key_id = keys.keys[0].id
else:
    keys = KeyList(open(local_file(KEY_FILE), 'rb').read())
    assert len(keys.keys) == 1, "No support for multiple keys yet"
    master_key_wrap = keys.keys[0]
    pw1 = getpass.getpass("master password? ").strip()
    wrap, local = master_key_wrap.schema.split('/')
    master_key_id = master_key_wrap.id
    assert wrap.startswith('scrypt-'), "only scrypt supported for key wrapper"
    s_enc_time = int(wrap.split('-')[1])
    try:
        aes_key = scrypt.decrypt(master_key_wrap.box_key, pw1, maxtime=ms_to_s(s_enc_time) * 10)
    except scrypt.error:
        print "Master password incorrect"
        sys.exit(1)
    do_encryption = partial(aes_encrypt_whole, aes_key)
    do_decryption = partial(aes_decrypt_whole, aes_key)

    validation = do_decryption(master_key_wrap.checksum)
    if validation != VALIDATION_STRING:
        print "Master password incorrect"
        sys.exit(1)

boxes = {}
def reload():
    global boxes
    all_files = os.listdir(the_dir)
    box_files = [f for f in all_files if f.endswith('.box')]

    boxes = {}
    for f in box_files:
        box = read_box(f)
        boxes[box.label] = box

    print "(loaded %d boxes)" % len(boxes)

type_labels = {
    BOX_LOGIN : 'Login',
}

def box_summary(b):
    return '{} ({})'.format(b.label, type_labels[b.box_type])

def cmd_list():
    bkeys = list(boxes)
    bkeys.sort(key=lambda k: k.lower())
    for x, k in enumerate(bkeys):
        print ' [{}] {}'.format(x+1, box_summary(boxes[k]))

def cmd_add():
    types = [BOX_LOGIN]
    print 'Choose box type:'
    for t in types:
       print '  ({}) {}'.format(t, type_labels[t])

    choice = raw_input('? ').strip().lower()
    if not choice.isdigit() or int(choice) not in types:
        print 'Invalid box type!'
        return

    typ = int(choice)
    if typ == BOX_LOGIN:
        while True:
            label = raw_input('Label? ').strip()
            if not label:
                print "Label required."
            else:
                break
        username = raw_input('Username? ').strip()
        password = raw_input('Password (echo is ON)? ')
        description = raw_input('Description? ')

        id = uuid4().hex
        box = Box(label=label)
        box.box_type = typ
        box.login = Login(username=username, password=password, description=description)
        write_box(id + '.box', box)
        return True

def cmd_show(cmd):
    parts = cmd.split()
    if len(parts) != 2:
        print "show takes exactly one argument: box # for display"
        return

    if not parts[1].isdigit():
        print "invalid box #"
        return

    bkeys = list(boxes)
    bkeys.sort(key=lambda k: k.lower())

    idx = int(parts[1])

    try:
        box_id = bkeys[idx - 1]
    except IndexError:
        print "invalid box #"
        return

    box = boxes[box_id]

    display_box(box)

def display_box(box):
    print '~' * 72
    print '{} (type: {})'.format(box.label, type_labels[box.box_type])
    print '-' * 40

    if box.box_type == BOX_LOGIN:
        lg = box.login
        if lg.description__exists and lg.description:
            print ' Description: %s' % lg.description
        if lg.username__exists and lg.username:
            print ' Username: %r' % lg.username
        if lg.password__exists and lg.password:
            print ' Password: %r' % lg.password

    print '~' * 72

def cli_loop():
    do_reload = True
    while True:
        if do_reload:
            reload()
            do_reload = False
        try:
            command = raw_input('> ').strip().lower()
        except EOFError:
            break
        if command in ('q', 'quit'):
            break
        elif command in ('l', 'list'):
            cmd_list()
        elif command in ('a', 'add'):
            do_reload = cmd_add()
        elif command.startswith('s') or command.startswith('show'):
            cmd_show(command)

    print "Quitting..."

cli_loop()
