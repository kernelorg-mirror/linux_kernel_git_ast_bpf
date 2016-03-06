struct align_bitmap {
	unsigned long word;
} ____cacheline_aligned_in_smp;

struct bitmap_tags {
	unsigned int max_tags;
	unsigned int map_nr;
	struct align_bitmap *map;
	unsigned int __percpu *tag_cache;
};
int bt_alloc_tag(struct bitmap_tags *bt);
void bt_free_tag(struct bitmap_tags *bt, unsigned int tag);
int bt_init(struct bitmap_tags *bt, int cnt);
void bt_destroy(struct bitmap_tags *bt);
