i386_ss.add(when: 'CONFIG_AEHD', if_false: files('aehd-stub.c'))

i386_softmmu_ss.add(when: 'CONFIG_AEHD', if_true: files(
  'aehd-all.c',
  'aehd.c',
  'aehd-cpu.c',
  'aehd-accel-ops.c',
))
