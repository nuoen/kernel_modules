tools/bazel run \          
  --config=akita \
  --config=use_source_tree_aosp \
  --config=no_download_gki_fips140 \              
  //modules/hookmodule:hookmodule_dist \                                         
  --gki_build_config_fragment=//private/devices/google/akita:akita_gki.fragment \
  --defconfig_fragment=//private/devices/google/akita:akita_gki.fragment \
  --sandbox_debug
  