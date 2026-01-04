#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';

let foundUnsafe = false;

const files = fs.readdirSync('.')
  .filter(file => file.endsWith('.svg'))
  .filter(file => fs.statSync(file).isFile());

if (files.length === 0) {
  console.log('No SVG files found');
  process.exit(0);
}

for (const file of files) {
  try {
    const svgContent = fs.readFileSync(file, 'utf8');
    
    const dom = new JSDOM('<!DOCTYPE html>');
    const DOMPurify = createDOMPurify(dom.window);
    
    const cleanSVG = DOMPurify.sanitize(svgContent, { 
      USE_PROFILES: { svg: true },
      KEEP_CONTENT: true
    });
    
    const issues = [];
    
    const scriptMatches = svgContent.match(/<script[\s>][\s\S]*?<\/script>/gi);
    if (scriptMatches) {
      issues.push(`Found ${scriptMatches.length} script tag(s)`);
    }
    
    const eventHandlers = svgContent.match(/\s(on\w+)\s*=/gi);
    if (eventHandlers) {
      const uniqueHandlers = [...new Set(eventHandlers.map(h => h.trim().toLowerCase()))];
      issues.push(`Found event handlers: ${uniqueHandlers.join(', ')}`);
    }
    
    if (/javascript:/gi.test(svgContent)) {
      issues.push('Found javascript: URLs');
    }
    
    const originalDOM = new JSDOM(svgContent, { contentType: 'image/svg+xml' });
    const sanitizedDOM = new JSDOM(cleanSVG, { contentType: 'image/svg+xml' });
    
    const externalUrlPattern = /^(https?|ftp):\/\//i;
    const imageElements = originalDOM.window.document.querySelectorAll('image');
    const useElements = originalDOM.window.document.querySelectorAll('use');

    imageElements.forEach((img, index) => {
      const href = img.getAttribute('href') || img.getAttribute('xlink:href');
      if (href && externalUrlPattern.test(href.trim())) {
        issues.push(`Found external URL in image element: ${href}`);
      }
    });

    useElements.forEach((use, index) => {
      const href = use.getAttribute('href') || use.getAttribute('xlink:href');
      if (href && externalUrlPattern.test(href.trim())) {
        issues.push(`Found external URL in use element: ${href}`);
      }
    });

    const originalScripts = originalDOM.window.document.querySelectorAll('script');
    const sanitizedScripts = sanitizedDOM.window.document.querySelectorAll('script');
    
    if (originalScripts.length > sanitizedScripts.length) {
      issues.push(`DOMPurify removed ${originalScripts.length - sanitizedScripts.length} script element(s)`);
    }
    
    const allElements = originalDOM.window.document.querySelectorAll('*');
    let eventHandlerCount = 0;
    allElements.forEach(el => {
      Array.from(el.attributes).forEach(attr => {
        if (attr.name.toLowerCase().startsWith('on')) {
          eventHandlerCount++;
        }
      });
    });
    
    if (eventHandlerCount > 0 && issues.length === 0) {
      const sanitizedAllElements = sanitizedDOM.window.document.querySelectorAll('*');
      let sanitizedEventHandlerCount = 0;
      sanitizedAllElements.forEach(el => {
        Array.from(el.attributes).forEach(attr => {
          if (attr.name.toLowerCase().startsWith('on')) {
            sanitizedEventHandlerCount++;
          }
        });
      });
      
      if (eventHandlerCount > sanitizedEventHandlerCount) {
        issues.push(`DOMPurify removed ${eventHandlerCount - sanitizedEventHandlerCount} event handler attribute(s)`);
      }
    }
    
    if (issues.length > 0) {
      console.log(`Unsafe content found in: ${file}`);
      issues.forEach(issue => console.log(`  - ${issue}`));
      foundUnsafe = true;
    }
  } catch (error) {
    console.error(`Error processing ${file}: ${error.message}`);
    foundUnsafe = true;
  }
}

if (foundUnsafe) {
  process.exit(1);
} else {
  console.log('No unsafe content found in SVG files');
  process.exit(0);
}

