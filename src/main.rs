/* Copyright 2025 Andrew Riachi
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use procfs;
use clap::Parser;

#[derive(Parser)]
#[command(version, about = "Reports process stack, heap, text, and data memory usage.", long_about = None)]
struct Args {
    ///Regex to match process cmdline against
    #[arg(short, long)]
    regex: Option<String>,

    ///If --regex is given, include children of matched processes, even if they don't match.
    #[arg(short = 'c', long, requires = "regex")]
    match_children: bool,
    
    ///Refresh interval in seconds
    #[arg(short, long, default_value_t = 1.0_f64)]
    interval: f64,
}


fn main() {
    let args = Args::parse();
    println!("Hello, world!");
}
