desc 'Build libudis86'
task :libudis86 do
  Dir.chdir('libudis86') do
  
    puts "\n=== Building libudis86 ==="
    system('mkdir ../build 2>/dev/null')
  
    puts "\n*** Running opgen.py ***"
    system('python opgen.py')
    
    puts "\n*** Compiling ***"
    system('clang -c -arch i386 -arch x86_64 *.c')
    system('libtool -static -o ../build/libudis86.a *.o')
  
  end
end

desc 'Build'
task :build => [:libudis86] do
  puts "\n=== Building ==="
  system('mkdir build 2>/dev/null')
  
  puts "\n*** Building GCC i386 ***"
  system('gcc -o build/test_gcc_i386 -arch i386 -framework CoreServices -L build -ludis86 *.c *.cp')
  
  puts "\n*** Building GCC x86_64 ***"
  system('gcc -o build/test_gcc_x86_64 -arch x86_64 -framework CoreServices -L build -ludis86 *.c *.cp')
  
  puts "\n*** Building Clang i386 ***"
  system('clang -o build/test_clang_i386 -arch i386 -framework CoreServices -L build -ludis86 *.c *.cp')
  
  puts "\n*** Building Clang x86_64 ***"
  system('clang -o build/test_clang_x86_64 -arch x86_64 -framework CoreServices -L build -ludis86 *.c *.cp')
end

desc 'Test'
task :test => [:build] do
  puts "\n=== Testing ==="
  
  puts "\n*** Testing GCC i386 ***"
  system('build/test_gcc_i386')
  puts '!!! FAILED !!!' if $?.exitstatus != 0
  
  puts "\n*** Testing GCC x86_64 ***"
  system('build/test_gcc_x86_64')
  puts '!!! FAILED !!!' if $?.exitstatus != 0
  
  puts "\n*** Testing Clang i386 ***"
  system('build/test_clang_i386')
  puts '!!! FAILED !!!' if $?.exitstatus != 0
  
  puts "\n*** Testing Clang x86_64 ***"
  system('build/test_clang_x86_64')
  puts '!!! FAILED !!!' if $?.exitstatus != 0
end

desc 'Clean up'
task :clean do
  system('rm -rf build')
  system('rm -rf libudis86/itab.c libudis86/itab.h libudis86/*.o')
end

task :default => [:clean, :test, :clean]