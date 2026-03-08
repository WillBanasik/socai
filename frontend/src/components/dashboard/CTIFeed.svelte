<script lang="ts">
  import { relativeTime } from '../../lib/utils/time';

  let { items }: { items: any[] } = $props();

  const tagColours: Record<string, string> = {
    actor: 'bg-red-500/20 text-red-400',
    malware: 'bg-orange-500/20 text-orange-400',
    campaign: 'bg-blue-500/20 text-blue-400',
    sector: 'bg-green-500/20 text-green-400',
  };

  function getTags(item: any): { type: string; name: string }[] {
    const tags: { type: string; name: string }[] = [];
    for (const a of item.threat_actors || []) tags.push({ type: 'actor', name: a });
    for (const m of item.malware || []) tags.push({ type: 'malware', name: m });
    for (const c of item.campaigns || []) tags.push({ type: 'campaign', name: c });
    for (const s of item.sectors || []) tags.push({ type: 'sector', name: s });
    return tags;
  }
</script>

<div class="bg-surface-700 border border-surface-600 rounded-xl p-4">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">CTI Feed</h3>
  <div class="space-y-2 max-h-[420px] overflow-y-auto">
    {#each items as item}
      {@const tags = getTags(item)}
      <div class="p-3 bg-surface-800 rounded-lg hover:border-accent-500/30 border border-transparent transition-colors">
        {#if item.link}
          <a href={item.link} target="_blank" rel="noopener" class="text-sm text-gray-200 hover:text-accent-400 font-medium">
            {item.name || item.title || 'Untitled'}
          </a>
        {:else}
          <p class="text-sm text-gray-200 font-medium">{item.name || item.title || 'Untitled'}</p>
        {/if}
        {#if item.description}
          <p class="text-xs text-gray-400 mt-1 line-clamp-2">{item.description}</p>
        {/if}
        <div class="flex items-center gap-2 mt-1 text-[10px] text-gray-500">
          {#if item.author}<span>{item.author}</span>{/if}
          {#if item.published}<span>{relativeTime(item.published)}</span>{/if}
        </div>
        {#if tags.length > 0}
          <div class="flex flex-wrap gap-1 mt-2">
            {#each tags as tag}
              <span class="px-1.5 py-0.5 rounded text-[10px] font-medium {tagColours[tag.type] || 'bg-gray-600/20 text-gray-400'}">
                {tag.name}
              </span>
            {/each}
          </div>
        {/if}
      </div>
    {/each}
    {#if items.length === 0}
      <p class="text-xs text-gray-500 py-4 text-center">No CTI feed data available</p>
    {/if}
  </div>
</div>
