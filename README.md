bitmap-injection-helper
---

Does what it says. But only for Halo 3. Takes in a Third Generation Blam Cache File, and ImageRaw (optionally 
MipMaps raw too) and preps the Raw content and injects it into the Cache file. Handles all the bullshit for you.

# Usage

Run the following command for a full usage list:
``` bash
$ BitmapInjectionHelper.exe -h
```

# Know Issues

* Images with a `MipMapCount` of 1 will inject incorrectly, Zedd is fixing that.
