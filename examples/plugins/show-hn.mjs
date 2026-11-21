// Example Oculon plugin: tracks Show HN launches with unusual traction.
// Copy to ~/.oculon/plugins/ (or your OCULON_PLUGINS folder), then:
//   oculon plugin list
//   oculon plugin run show-hn.top
export default {
  name: 'show-hn',
  version: '0.1.0',
  description: 'Show HN launches with unusual traction in the last 48 hours',
  tools: [
    {
      name: 'top',
      description: 'Show HN posts from the last 48 hours with at least `min_points` points; strong ones become signals.',
      inputSchema: { type: 'object', properties: { min_points: { type: 'number', description: 'default 100' } }, additionalProperties: false },
      async run(api, args) {
        const min = Number(args.min_points ?? 100);
        const since = Math.floor(api.now().getTime() / 1000) - 48 * 3600;
        const r = await api.get(`https://hn.algolia.com/api/v1/search?tags=show_hn&hitsPerPage=50&numericFilters=${encodeURIComponent(`created_at_i>${since},points>${min}`)}`);
        const hits = (r.data?.hits ?? []).sort((a, b) => b.points - a.points);
        for (const h of hits.filter((x) => x.points >= 300)) {
          api.signal({ key: h.objectID, title: `Show HN taking off: ${h.title}`, score: Math.min(80, 40 + h.points / 20), evidence: [{ source: 'hackernews', text: `${h.points} points, ${h.num_comments} comments`, url: `https://news.ycombinator.com/item?id=${h.objectID}` }] });
        }
        return { source: r.prov.status, posts: hits.map((h) => ({ title: h.title, points: h.points, comments: h.num_comments, url: `https://news.ycombinator.com/item?id=${h.objectID}` })) };
      },
    },
  ],
};
