const { DateTime } = require("luxon");

module.exports = function(eleventyConfig) {
  // CRITICAL: Always perform full builds, never incremental
  // Incremental builds don't delete stale files, causing 15,000+ CVE issue
  eleventyConfig.setUseGitIgnore(false);
  
  // Copy static assets
  eleventyConfig.addPassthroughCopy("assets");
  eleventyConfig.addPassthroughCopy("api");
  
  // Watch additional directories
  eleventyConfig.addWatchTarget("./assets/");
  eleventyConfig.addWatchTarget("./api/");
  
  // Date filters
  eleventyConfig.addFilter("readableDate", dateObj => {
    return DateTime.fromJSDate(dateObj, {zone: 'utc'}).toFormat("dd LLL yyyy");
  });
  
  eleventyConfig.addFilter("htmlDateString", (dateObj) => {
    return DateTime.fromJSDate(dateObj, {zone: 'utc'}).toFormat('yyyy-LL-dd');
  });
  
  // JSON filter for Alpine.js
  eleventyConfig.addFilter("json", (value) => {
    return JSON.stringify(value);
  });
  
  // CVE filters
  eleventyConfig.addFilter("cveYear", (cveId) => {
    const match = cveId.match(/CVE-(\d{4})/);
    return match ? match[1] : 'Unknown';
  });
  
  eleventyConfig.addFilter("riskLevel", (score) => {
    if (score >= 90) return 'CRITICAL';
    if (score >= 70) return 'HIGH';
    if (score >= 50) return 'ELEVATED';
    if (score >= 30) return 'MODERATE';
    return 'LOW';
  });
  
  eleventyConfig.addFilter("confidenceColor", (confidence) => {
    if (confidence >= 0.8) return 'text-green-600';
    if (confidence >= 0.6) return 'text-yellow-600';
    return 'text-red-600';
  });
  
  // Performance optimizations
  eleventyConfig.setQuietMode(true);
  
  // Template formats
  eleventyConfig.setTemplateFormats([
    "md", "njk", "html", "liquid", "11ty.js"
  ]);
  
  // Markdown configuration
  eleventyConfig.setLibrary("md", require("@11ty/eleventy/lib/TemplateEngines/MarkdownTemplateEngine").getMarkdownLib());
  
  // Global data
  eleventyConfig.addGlobalData("site", {
    title: "NOPE - Network Operational Patch Evaluator",
    description: "Predictive CVE Intelligence Platform with EPSS filtering",
    url: "https://williamzujkowski.github.io/NOPE",
    buildDate: new Date(),
    version: "3.0.0"
  });
  
  // Collections for CVE data
  eleventyConfig.addCollection("highRiskPredictions", function(collectionApi) {
    // This will be populated by the Python pipeline
    return [];
  });
  
  eleventyConfig.addCollection("earlyWarnings", function(collectionApi) {
    // This will be populated by the early warning system
    return [];
  });
  
  // Performance: disable fancy processing for production
  if (process.env.NODE_ENV === 'production') {
    eleventyConfig.setDataDeepMerge(false);
  }
  
  return {
    templateFormats: ["md", "njk", "html", "liquid"],
    markdownTemplateEngine: "njk",
    htmlTemplateEngine: "njk",
    dataTemplateEngine: "njk",
    
    dir: {
      input: ".",
      includes: "_includes",
      data: "_data",
      output: "_site"
    }
  };
};