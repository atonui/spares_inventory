const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const context={Intl,Date};
vm.createContext(context);
vm.runInContext(fs.readFileSync('static/temporal.js','utf8'),context);
const time=context.InventoryTime;

test('explicit UTC and offset instants have identical display in a selected zone',()=>{
 assert.equal(time.formatInstant('2026-10-12T09:00:00Z','Africa/Nairobi'),'2026-10-12 12:00:00 UTC+03:00');
 assert.equal(time.formatInstant('2026-10-12T12:00:00+03:00','America/New_York'),time.formatInstant('2026-10-12T09:00:00Z','America/New_York'));
 assert.equal(time.formatInstant('2026-10-12T09:00:00.123456Z','Asia/Kathmandu'),'2026-10-12 14:45:00 UTC+05:45');
});

test('public parsing does not infer offsets or normalise invalid dates',()=>{
 for(const value of [null,'','2026-10-12','2026-10-12T09:00:00','2026-10-12 09:00:00Z',
  '2026-02-30T09:00:00Z','2026-10-12T24:00:00Z','2026-10-12T09:00:00+01:99','0000-01-01T00:00:00Z']){
  assert.equal(Number.isNaN(time.parseInstant(value)),true,String(value));
  assert.equal(time.formatInstant(value,'UTC'),'Unknown');
 }
});

test('calendar dates remain dates regardless of viewer timezone',()=>{
 for(const date of ['2026-10-12','2024-02-29','0001-01-01'])assert.equal(time.formatDate(date),date);
 for(const date of ['2026-02-29','2026-02-30','2026-10-12T00:00:00Z','0000-01-01',null])assert.equal(time.formatDate(date),'Unknown');
});

test('zones reject abbreviations, invalid and host-specific identifiers',()=>{
 for(const zone of ['IST','BST','+03:00','posix/Africa/Nairobi','right/Africa/Nairobi','Africa/Unknown','',null])assert.equal(time.isValidZone(zone),false,String(zone));
 for(const zone of ['UTC','Africa/Nairobi','America/New_York','Asia/Kathmandu'])assert.equal(time.isValidZone(zone),true);
 assert.equal(time.formatInstant('2026-10-12T09:00:00Z','IST'),'Unknown');
});

test('daylight saving display distinguishes both repeated local hours',()=>{
 assert.equal(time.formatInstant('2026-11-01T05:30:00Z','America/New_York'),'2026-11-01 01:30:00 UTC-04:00');
 assert.equal(time.formatInstant('2026-11-01T06:30:00Z','America/New_York'),'2026-11-01 01:30:00 UTC-05:00');
 assert.equal(time.parseInstant('2026-11-01T06:30:00Z')-time.parseInstant('2026-11-01T05:30:00Z'),3600000);
});

test('business today and calendar arithmetic use dates without viewer offsets',()=>{
 const instant='2026-10-11T22:00:00Z';
 assert.equal(time.today('Africa/Nairobi',instant),'2026-10-12');
 assert.equal(time.today('America/New_York',instant),'2026-10-11');
 assert.equal(time.addDays('2026-03-08',1),'2026-03-09');
 assert.equal(time.addDays('2024-03-01',-1),'2024-02-29');
 assert.equal(time.addDays('9999-12-31',1),'Unknown');
 assert.equal(time.daysBetween('2026-03-08','2026-03-09'),1);
 assert.equal(Number.isNaN(time.daysBetween('bad','2026-10-12')),true);
});

test('report formatting uses supplied report zone independently of personal display',()=>{
 const instant='2026-10-12T09:00:00Z', report={timezone:'Africa/Nairobi'};
 assert.equal(time.formatInstant(instant,report.timezone),'2026-10-12 12:00:00 UTC+03:00');
 assert.equal(time.formatInstant(instant,'America/New_York'),'2026-10-12 05:00:00 UTC-04:00');
 assert.equal(time.formatInstant(instant,report.timezone),'2026-10-12 12:00:00 UTC+03:00');
});

test('local year overflow and BCE values are not displayed as ordinary positive years',()=>{
 assert.equal(time.formatInstant('0001-01-01T00:00:00Z','America/New_York'),'Unknown');
 assert.equal(time.today('America/New_York','0001-01-01T00:00:00Z'),'Unknown');
 assert.equal(time.formatInstant('9999-12-31T23:59:59Z','Africa/Nairobi'),'Unknown');
 assert.equal(time.formatInstant('0001-01-01T00:00:00Z','UTC'),'0001-01-01 00:00:00 UTC');
});
