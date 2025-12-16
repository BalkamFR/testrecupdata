rm -rf .git
git init
cp -r Documents/web/ testrecupdata
git add .
git commit -m "add all"
git branch -M main
git remote add origin git@github.com:BalkamFR/testrecupdata.git
git push --set-upstream origin main -f

